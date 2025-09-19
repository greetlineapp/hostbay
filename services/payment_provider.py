"""
Payment provider factory for switching between DynoPay and BlockBee
Provides unified interface for cryptocurrency payment processing
Enhanced with payment intents to prevent duplicate address creation
"""

import os
import logging
from typing import Dict, Optional, Union
from services.dynopay import DynoPayService
from services.blockbee import BlockBeeService
# Import payment intent functions for idempotent payment processing
from database import (
    create_payment_intent, get_payment_intent_by_order_id, 
    update_payment_intent_status, get_active_payment_intent,
    # CRITICAL: Import atomic claiming functions for concurrency safety
    claim_intent_for_address_creation, release_intent_claim, wait_for_intent_address_creation
)
from performance_monitor import monitor_performance

logger = logging.getLogger(__name__)

class PaymentProviderFactory:
    """Factory for creating and managing payment provider instances"""
    
    _dynopay_instance = None
    _blockbee_instance = None
    
    @classmethod
    def get_provider_name(cls) -> str:
        """Get the currently configured payment provider name"""
        return os.getenv('CRYPTO_PAYMENT_PROVIDER', 'blockbee').lower()
    
    @classmethod
    def get_dynopay_service(cls) -> DynoPayService:
        """Get DynoPay service instance (singleton)"""
        if cls._dynopay_instance is None:
            cls._dynopay_instance = DynoPayService()
        return cls._dynopay_instance
    
    @classmethod
    def get_blockbee_service(cls) -> BlockBeeService:
        """Get BlockBee service instance (singleton)"""
        if cls._blockbee_instance is None:
            cls._blockbee_instance = BlockBeeService()
        return cls._blockbee_instance
    
    @classmethod
    def get_primary_provider(cls) -> Union[DynoPayService, BlockBeeService]:
        """Get the primary payment provider based on configuration"""
        provider_name = cls.get_provider_name()
        
        if provider_name == 'dynopay':
            provider = cls.get_dynopay_service()
            if provider.is_available():
                logger.info("✅ Using DynoPay as primary payment provider")
                return provider
            else:
                logger.warning("⚠️ DynoPay not available, falling back to BlockBee")
                return cls.get_blockbee_service()
        
        elif provider_name == 'blockbee':
            provider = cls.get_blockbee_service()
            logger.info("✅ Using BlockBee as primary payment provider")
            return provider
        
        else:
            logger.warning(f"⚠️ Unknown payment provider '{provider_name}', using DynoPay as default")
            provider = cls.get_dynopay_service()
            if provider.is_available():
                return provider
            else:
                logger.warning("⚠️ DynoPay not available, falling back to BlockBee")
                return cls.get_blockbee_service()
    
    @classmethod
    def get_backup_provider(cls) -> Union[DynoPayService, BlockBeeService]:
        """Get the backup payment provider"""
        provider_name = cls.get_provider_name()
        
        if provider_name == 'dynopay':
            logger.info("✅ Using BlockBee as backup payment provider")
            return cls.get_blockbee_service()
        else:
            dynopay = cls.get_dynopay_service()
            if dynopay.is_available():
                logger.info("✅ Using DynoPay as backup payment provider")
                return dynopay
            else:
                logger.warning("⚠️ No backup provider available")
                return cls.get_blockbee_service()
    
    @classmethod
    async def create_payment_address_with_fallback(cls, currency: str, order_id: str, value: float, user_id: int) -> Optional[Dict]:
        """
        Create payment address with atomic concurrency protection using CAS pattern
        FIXED: Prevents race conditions that could create multiple external addresses
        """
        logger.info(f"🔒 ATOMIC: Creating payment address for order {order_id}, amount: ${value}, currency: {currency}")
        
        # Step 1: Check for existing completed payment intent (idempotency)
        existing_intent = await get_payment_intent_by_order_id(order_id)
        if existing_intent:
            logger.info(f"✅ IDEMPOTENCY: Found existing payment intent for order {order_id}")
            if existing_intent.get('payment_address') and existing_intent.get('status') == 'address_created':
                # Return existing payment address data
                logger.info(f"✅ IDEMPOTENCY: Returning existing payment address for order {order_id}")
                return {
                    'address': existing_intent['payment_address'],
                    'order_id': order_id,
                    'amount': existing_intent['amount'],
                    'currency': existing_intent['currency'],
                    'provider': existing_intent.get('payment_provider', 'unknown'),
                    'status': 'existing_address_returned'
                }
            elif existing_intent.get('status') == 'creating_address':
                # Another process is currently creating the address - wait for completion
                logger.info(f"⏰ CONCURRENCY: Another process creating address for order {order_id} - waiting...")
                completed_intent = await wait_for_intent_address_creation(existing_intent['id'], max_wait_seconds=30)
                if completed_intent and completed_intent.get('payment_address'):
                    logger.info(f"✅ CONCURRENCY: Address creation completed by other process for order {order_id}")
                    return {
                        'address': completed_intent['payment_address'],
                        'order_id': order_id,
                        'amount': completed_intent['amount'],
                        'currency': completed_intent['currency'],
                        'provider': completed_intent.get('payment_provider', 'unknown'),
                        'status': 'address_created_by_other_process'
                    }
                else:
                    logger.warning(f"⚠️ CONCURRENCY: Timeout or failure waiting for address creation for order {order_id}")
                    return None
            else:
                logger.info(f"ℹ️ Payment intent exists in status {existing_intent.get('status')} for order {order_id}")
        
        # Step 2: Create new payment intent if none exists
        if not existing_intent:
            # Determine provider name
            primary_provider = cls.get_primary_provider()
            provider_name = 'dynopay' if isinstance(primary_provider, DynoPayService) else 'blockbee'
            
            intent_id = await create_payment_intent(order_id, user_id, value, 'USD', currency, provider_name)
            if not intent_id:
                logger.error(f"❌ Failed to create payment intent for order {order_id}")
                return None
            logger.info(f"✅ Created payment intent {intent_id} for order {order_id}")
        else:
            intent_id = existing_intent['id']
            logger.info(f"ℹ️ Using existing payment intent {intent_id} for order {order_id}")
        
        # Step 3: ATOMIC CLAIMING - Try to claim intent for address creation
        primary_provider = cls.get_primary_provider()
        provider_name = 'DynoPay' if isinstance(primary_provider, DynoPayService) else 'BlockBee'
        
        import uuid
        claim_key = str(uuid.uuid4())
        
        # Attempt atomic claim
        claimed_intent = await claim_intent_for_address_creation(intent_id, provider_name.lower(), claim_key)
        
        if not claimed_intent:
            # Intent already claimed by another process - wait for completion
            logger.info(f"⏰ ATOMIC: Intent {intent_id} already claimed - waiting for completion...")
            completed_intent = await wait_for_intent_address_creation(intent_id, max_wait_seconds=30)
            if completed_intent and completed_intent.get('payment_address'):
                logger.info(f"✅ ATOMIC: Address creation completed by other process for intent {intent_id}")
                return {
                    'address': completed_intent['payment_address'],
                    'order_id': order_id,
                    'amount': completed_intent['amount'],
                    'currency': completed_intent['currency'],
                    'provider': completed_intent.get('payment_provider', 'unknown'),
                    'status': 'address_created_by_other_process'
                }
            else:
                logger.warning(f"⚠️ ATOMIC: Timeout or failure waiting for address creation for intent {intent_id}")
                return None
        
        logger.info(f"🔒 ATOMIC: Successfully claimed intent {intent_id} - proceeding with address creation")
        
        # Step 4: Try primary provider with claimed intent (propagate idempotency key)
        try:
            # FIXED: Propagate idempotency key to provider for true provider-level idempotency
            result = await primary_provider.create_payment_address(
                currency, order_id, value, user_id, idempotency_key=claim_key
            )
            if result and result.get('address'):
                # Successfully created address - release claim with success
                await release_intent_claim(
                    intent_id, 
                    provider_name.lower(), 
                    success=True,
                    payment_address=result['address'],
                    external_order_id=result.get('order_id')
                )
                logger.info(f"✅ ATOMIC: Payment address created successfully with {provider_name} for intent {intent_id}")
                result['status'] = 'new_address_created_atomic'
                return result
        except Exception as e:
            logger.error(f"❌ Primary provider ({provider_name}) failed for intent {intent_id}: {e}")
        
        # Step 5: Try backup provider if primary fails
        backup_provider = cls.get_backup_provider()
        backup_provider_name = 'DynoPay' if isinstance(backup_provider, DynoPayService) else 'BlockBee'
        
        if backup_provider != primary_provider:
            try:
                # FIXED: Propagate idempotency key to backup provider too
                result = await backup_provider.create_payment_address(
                    currency, order_id, value, user_id, idempotency_key=claim_key
                )
                if result and result.get('address'):
                    # Successfully created address - release claim with success
                    await release_intent_claim(
                        intent_id, 
                        backup_provider_name.lower(), 
                        success=True,
                        payment_address=result['address'],
                        external_order_id=result.get('order_id')
                    )
                    logger.info(f"✅ ATOMIC: Payment address created with backup provider ({backup_provider_name}) for intent {intent_id}")
                    result['status'] = 'new_address_created_backup_atomic'
                    return result
            except Exception as e:
                logger.error(f"❌ Backup provider ({backup_provider_name}) also failed for intent {intent_id}: {e}")
        
        # Step 6: All providers failed - release claim with failure
        await release_intent_claim(intent_id, provider_name.lower(), success=False)
        logger.error(f"❌ ATOMIC: All payment providers failed to create payment address for intent {intent_id}")
        return None
    
    @classmethod
    async def check_payment_status_with_fallback(cls, currency: str, payment_address: str) -> Optional[Dict]:
        """Check payment status with automatic fallback"""
        
        # Try both providers since we don't know which one created the address
        providers = [cls.get_primary_provider(), cls.get_backup_provider()]
        
        for provider in providers:
            try:
                result = await provider.check_payment_status(currency, payment_address)
                if result:
                    provider_name = 'DynoPay' if isinstance(provider, DynoPayService) else 'BlockBee'
                    logger.info(f"✅ Payment status retrieved from {provider_name}")
                    return result
            except Exception as e:
                provider_name = 'DynoPay' if isinstance(provider, DynoPayService) else 'BlockBee'
                logger.warning(f"⚠️ Status check failed on {provider_name}: {e}")
        
        logger.warning("⚠️ Payment status could not be retrieved from any provider")
        return None

# Convenience functions for direct usage
async def create_payment_address(currency: str, order_id: str, value: float, user_id: int) -> Optional[Dict]:
    """Create payment address using the configured provider with fallback"""
    return await PaymentProviderFactory.create_payment_address_with_fallback(currency, order_id, value, user_id)

async def check_payment_status(currency: str, payment_address: str) -> Optional[Dict]:
    """Check payment status using available providers"""
    return await PaymentProviderFactory.check_payment_status_with_fallback(currency, payment_address)

def get_current_provider_name() -> str:
    """Get the name of the currently active payment provider"""
    return PaymentProviderFactory.get_provider_name()

def is_dynopay_primary() -> bool:
    """Check if DynoPay is the primary provider"""
    return PaymentProviderFactory.get_provider_name() == 'dynopay'

def is_blockbee_primary() -> bool:
    """Check if BlockBee is the primary provider"""
    return PaymentProviderFactory.get_provider_name() == 'blockbee'