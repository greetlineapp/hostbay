"""
Domain Registration Orchestrator - Single Source of Truth for Domain Registration Notifications

This module provides a centralized orchestrator for domain registration processing that eliminates
duplicate notifications by using database-level processing locks and notification deduplication.

Architecture:
- Atomic status state machine: pending → processing → completed
- Notification ledger with UNIQUE constraints
- Single entry point for all domain registration flows
- Idempotency guards to prevent race conditions
"""

import logging
import time
import asyncio
from typing import Optional, Dict, Any, Tuple
from database import (
    execute_query, execute_update, save_cloudflare_zone, get_or_create_user, 
    save_domain, create_registration_intent, update_intent_status, 
    finalize_domain_registration
)
from localization import t
from admin_alerts import send_critical_alert, send_error_alert, send_warning_alert

logger = logging.getLogger(__name__)

# ====================================================================
# DOMAIN REGISTRATION ORCHESTRATOR - SINGLE SOURCE OF TRUTH
# ====================================================================

class RegistrationProcessingError(Exception):
    """Custom exception for registration processing errors"""
    pass

class DuplicateRegistrationError(Exception):
    """Raised when attempting to process an already completed registration"""
    pass

class RegistrationOrchestrator:
    """
    Centralized orchestrator for domain registration processing.
    
    Eliminates duplicate notifications through:
    1. Atomic status state machine (pending → processing → completed)
    2. Notification deduplication ledger
    3. Single entry point for all registration flows
    """
    
    def __init__(self):
        self.crypto_name_map = {
            'btc': 'Bitcoin', 'ltc': 'Litecoin', 'doge': 'Dogecoin',
            'eth': 'Ethereum', 'usdt_trc20': 'USDT (TRC20)', 'usdt_erc20': 'USDT (ERC20)'
        }
    
    async def start_registration(
        self,
        order_id: int,  # FIXED: Now accepts integer order ID from database
        user_id: int, 
        domain_name: str,
        payment_details: Optional[Dict[str, Any]] = None,
        query_adapter: Optional[Any] = None,
        lang_code: str = 'en'
    ) -> Dict[str, Any]:
        """
        Single entry point for domain registration processing.
        
        Uses atomic database operations to prevent duplicate processing and notifications.
        
        Args:
            order_id: Unique order identifier
            user_id: Internal user ID  
            domain_name: Domain to register
            payment_details: Payment information for notifications
            query_adapter: For sending user notifications
            
        Returns:
            Dict with processing results and status
        """
        logger.info(f"🎯 ORCHESTRATOR: Starting registration for order {order_id}, domain {domain_name}")
        
        try:
            # Step 1: Claim processing lock with atomic operation
            processing_claimed = await self._claim_processing_lock(order_id, user_id, domain_name)
            if not processing_claimed:
                logger.warning(f"🚫 ORCHESTRATOR: Registration already claimed/completed for order {order_id}")
                return {'status': 'already_processed', 'order_id': order_id}
            
            # Step 2: Send initial progress notification (with deduplication)
            await self._send_notification_safe(
                order_id=order_id,
                user_id=user_id,
                message_type='payment_confirmed_progress', 
                domain_name=domain_name,
                payment_details=payment_details,
                query_adapter=query_adapter,
                lang_code=lang_code
            )
            
            # Step 3: Execute domain registration workflow
            registration_result = await self._execute_registration_workflow(
                order_id=order_id,
                user_id=user_id,
                domain_name=domain_name,
                payment_details=payment_details,
                query_adapter=query_adapter
            )
            
            # Step 4: Send final notification based on result
            if registration_result.get('success'):
                await self._send_notification_safe(
                    order_id=order_id,
                    user_id=user_id,
                    message_type='registration_success',
                    domain_name=domain_name,
                    payment_details=payment_details,
                    query_adapter=query_adapter,
                    registration_result=registration_result,
                    lang_code=lang_code
                )
                
                # Step 5: Mark order as completed
                await self._complete_registration(order_id, registration_result)
                
            else:
                await self._send_notification_safe(
                    order_id=order_id,
                    user_id=user_id,
                    message_type='registration_failure',
                    domain_name=domain_name,
                    payment_details=payment_details,
                    query_adapter=query_adapter,
                    error=registration_result.get('error', 'Unknown error'),
                    lang_code=lang_code
                )
                
                # Mark order as failed
                await self._fail_registration(order_id, registration_result.get('error', 'Unknown error'))
            
            logger.info(f"✅ ORCHESTRATOR: Registration completed for order {order_id}")
            return registration_result
            
        except DuplicateRegistrationError as e:
            logger.warning(f"🚫 ORCHESTRATOR: {e}")
            return {'status': 'duplicate_prevented', 'order_id': order_id}
        except Exception as e:
            logger.error(f"❌ ORCHESTRATOR: Registration failed for order {order_id}: {e}")
            # Send admin alert for registration orchestrator failure
            await send_critical_alert(
                "RegistrationOrchestrator", 
                f"Domain registration failed for order {order_id}: {str(e)}",
                "domain_registration",
                {
                    "order_id": order_id,
                    "user_id": user_id,
                    "domain_name": domain_name,
                    "exception": str(e),
                    "payment_details": payment_details
                }
            )
            await self._fail_registration(order_id, str(e))
            return {'status': 'error', 'order_id': order_id, 'error': str(e)}
    
    async def _claim_processing_lock(self, order_id: int, user_id: int, domain_name: str) -> bool:
        """
        Atomically claim processing lock using database status state machine.
        
        Uses UPDATE ... WHERE to ensure only one process can claim an order.
        
        Returns True if lock claimed, False if already claimed/completed.
        """
        logger.debug(f"🔒 ORCHESTRATOR: Attempting to claim processing lock for order {order_id}")
        
        try:
            # Atomic update: claim processing lock only if status is 'pending' or 'paid'
            rows_updated = await execute_update("""
                UPDATE domain_orders 
                SET status = 'processing', 
                    updated_at = CURRENT_TIMESTAMP,
                    processing_started_at = CURRENT_TIMESTAMP
                WHERE id = %s 
                AND user_id = %s 
                AND domain_name = %s
                AND status IN ('pending', 'paid')
            """, (order_id, user_id, domain_name))
            
            if rows_updated > 0:
                logger.info(f"✅ ORCHESTRATOR: Processing lock claimed for order {order_id}")
                return True
            else:
                # Check current status to understand why lock wasn't claimed
                existing_orders = await execute_query(
                    "SELECT status FROM domain_orders WHERE id = %s", 
                    (order_id,)
                )
                
                if existing_orders:
                    current_status = existing_orders[0]['status']
                    logger.warning(f"🚫 ORCHESTRATOR: Cannot claim lock - order {order_id} status: {current_status}")
                    
                    if current_status in ('completed', 'processing'):
                        raise DuplicateRegistrationError(f"Order {order_id} already {current_status}")
                else:
                    logger.error(f"❌ ORCHESTRATOR: Order {order_id} not found in database")
                
                return False
                
        except DuplicateRegistrationError:
            raise
        except Exception as e:
            logger.error(f"❌ ORCHESTRATOR: Failed to claim processing lock for order {order_id}: {e}")
            return False
    
    async def _send_notification_safe(
        self,
        order_id: int,
        user_id: int,
        message_type: str,
        domain_name: str,
        payment_details: Optional[Dict] = None,
        query_adapter: Optional[Any] = None,
        registration_result: Optional[Dict] = None,
        error: Optional[str] = None,
        lang_code: str = 'en'
    ) -> bool:
        """
        Send notification with deduplication protection.
        
        Uses notification ledger with UNIQUE constraints to prevent duplicate messages.
        """
        logger.debug(f"📧 ORCHESTRATOR: Sending {message_type} notification for order {order_id}")
        
        try:
            # Step 1: Check if notification already sent using deduplication ledger
            # Convert integer order_id to string for varchar column compatibility
            existing_notifications = await execute_query("""
                SELECT id, sent_at FROM domain_notifications 
                WHERE order_id = %s AND message_type = %s
            """, (str(order_id), message_type))
            
            if existing_notifications:
                logger.warning(f"🚫 ORCHESTRATOR: {message_type} notification already sent for order {order_id}")
                return False
            
            # Step 2: Generate notification message
            message = self._generate_notification_message(
                message_type=message_type,
                domain_name=domain_name,
                payment_details=payment_details,
                registration_result=registration_result,
                error=error,
                lang_code=lang_code
            )
            
            # Step 3: Record notification in ledger (with deduplication protection)
            try:
                await execute_update("""
                    INSERT INTO domain_notifications (order_id, message_type, user_id, message_content, sent_at)
                    VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
                """, (str(order_id), message_type, user_id, message))
                
                logger.info(f"📧 ORCHESTRATOR: {message_type} notification recorded for order {order_id}")
                
            except Exception as db_error:
                # Check if this is a duplicate key error (expected for race conditions)
                if 'duplicate key' in str(db_error).lower() or 'unique constraint' in str(db_error).lower():
                    logger.warning(f"🚫 ORCHESTRATOR: Duplicate {message_type} notification prevented for order {order_id}")
                    return False
                else:
                    # Unexpected database error
                    logger.error(f"❌ ORCHESTRATOR: Database error recording {message_type} notification: {db_error}")
                    # Continue to send notification even if recording fails
            
            # Step 4: Send notification to user
            if query_adapter:
                await self._send_message_to_user(query_adapter, message)
                logger.info(f"✅ ORCHESTRATOR: {message_type} notification sent to user for order {order_id}")
            else:
                logger.warning(f"⚠️ ORCHESTRATOR: No query_adapter provided for {message_type} notification")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ ORCHESTRATOR: Failed to send {message_type} notification for order {order_id}: {e}")
            return False
    
    def _generate_notification_message(
        self,
        message_type: str,
        domain_name: str,
        payment_details: Optional[Dict] = None,
        registration_result: Optional[Dict] = None,
        error: Optional[str] = None,
        lang_code: str = 'en'
    ) -> str:
        """Generate notification message based on type and context."""
        
        if message_type == 'payment_confirmed_progress':
            return self._generate_progress_message(domain_name, payment_details, lang_code)
        elif message_type == 'registration_success':
            return self._generate_success_message(domain_name, payment_details, registration_result, lang_code)
        elif message_type == 'registration_failure':
            return self._generate_failure_message(domain_name, payment_details, error, lang_code)
        else:
            return t('services.registration_orchestrator.progress_messages.finalizing', lang_code, domain=domain_name)
    
    def _generate_progress_message(self, domain_name: str, payment_details: Optional[Dict], lang_code: str = 'en') -> str:
        """Generate payment confirmed + registration progress message."""
        
        if payment_details:
            # Fix key mapping - webhook uses different keys than expected
            amount_usd = payment_details.get('amount_usd') or payment_details.get('expected_usd', 0)
            amount_crypto = payment_details.get('amount_crypto') or payment_details.get('received_crypto', 0)
            currency = payment_details.get('currency') or payment_details.get('crypto_currency', 'CRYPTO')
            
            crypto_name = self.crypto_name_map.get(currency.lower(), currency.upper())
            
            # Compact, focused message
            message = f"✅ <b>Payment Confirmed</b>\n"
            message += f"💰 ${amount_usd:.2f} from {amount_crypto:.6f} {crypto_name}\n\n"
            
            # Add overpayment info if present
            overpay = payment_details.get('overpayment_amount', 0)
            if overpay > 0:
                message += f"💵 Overpaid: ${overpay:.2f}"
                if payment_details.get('overpayment_credited'):
                    message += " ✅ credited\n"
                else:
                    message += " ⚠️ contact support\n"
                message += "\n"
            
            # Compact progress
            message += f"🚀 <b>Registering {domain_name}</b>\n"
            message += f"🔄 Creating DNS zone...\n"
            message += f"⏳ Registering domain...\n"
            message += f"<i>Takes 30-60 seconds</i>"
        else:
            # Fallback - more compact
            message = f"🚀 <b>Registering {domain_name}</b>\n\n"
            message += f"✅ Payment confirmed\n"
            message += f"🔄 Creating DNS zone...\n"
            message += f"⏳ Registering domain..."
        
        return message
    
    def _generate_success_message(
        self, 
        domain_name: str, 
        payment_details: Optional[Dict], 
        registration_result: Optional[Dict],
        lang_code: str = 'en'
    ) -> str:
        """Generate registration success message."""
        
        # Prepare variables for translation
        kwargs = {'domain': domain_name}
        
        if payment_details:
            amount_usd = payment_details.get('amount_usd') or payment_details.get('expected_usd', 0)
            kwargs['amount'] = f"{float(amount_usd):.2f}"
        else:
            kwargs['amount'] = '0.00'
        
        if registration_result and registration_result.get('cloudflare_zone'):
            cf_zone = registration_result['cloudflare_zone']
            nameservers = cf_zone.get('name_servers', [])[:2]
            if nameservers:
                kwargs['nameservers'] = ', '.join(nameservers)
            else:
                kwargs['nameservers'] = 'Cloudflare'
        else:
            kwargs['nameservers'] = 'Cloudflare'
        
        # Use translation system to generate the message
        return t('services.registration_orchestrator.success_messages.registration_complete', lang_code, **kwargs)
    
    def _generate_failure_message(
        self, 
        domain_name: str, 
        payment_details: Optional[Dict], 
        error: Optional[str],
        lang_code: str = 'en'
    ) -> str:
        """Generate registration failure message."""
        
        # Prepare variables for translation
        kwargs = {
            'domain': domain_name,
            'error': error or t('services.common.errors.unknown_error', lang_code),
            'support_contact': 'Hostbay_support'
        }
        
        if payment_details:
            amount_usd = payment_details.get('amount_usd') or payment_details.get('expected_usd', 0)
            kwargs['amount'] = f"{float(amount_usd):.2f}"
        else:
            kwargs['amount'] = '0.00'
        
        # Use translation system to generate the message
        return t('services.registration_orchestrator.error_messages.registration_failed', lang_code, **kwargs)
    
    async def _send_message_to_user(self, query_adapter: Any, message: str):
        """Send message to user via query adapter."""
        try:
            if hasattr(query_adapter, 'send_message_to_user'):
                await query_adapter.send_message_to_user(message, parse_mode='HTML')
            elif hasattr(query_adapter, 'user_id'):
                # Use webhook-style messaging for non-telegram contexts
                from webhook_handler import queue_user_message
                queue_user_message(query_adapter.user_id, message, parse_mode='HTML')
            else:
                logger.warning("Query adapter doesn't support message sending")
        except Exception as e:
            logger.error(f"Failed to send message to user: {e}")
    
    async def _execute_registration_workflow(
        self,
        order_id: int,
        user_id: int,
        domain_name: str,
        payment_details: Optional[Dict],
        query_adapter: Optional[Any]
    ) -> Dict[str, Any]:
        """
        Execute the complete domain registration workflow.
        
        This includes:
        1. Cloudflare zone creation  
        2. OpenProvider domain registration
        3. Database finalization
        """
        logger.info(f"🔄 ORCHESTRATOR: Executing registration workflow for {domain_name}")
        
        try:
            # Phase 1: Cloudflare Zone Creation
            logger.info(f"🔄 Phase 1: Creating Cloudflare zone for {domain_name}")
            cloudflare_result = await self._create_cloudflare_zone(user_id, domain_name)
            
            if not cloudflare_result.get('success'):
                return {
                    'success': False,
                    'error': f"DNS zone creation failed: {cloudflare_result.get('error', 'Unknown error')}",
                    'phase': 'cloudflare_zone'
                }
            
            # Zone creation progress handled by payment_confirmed_progress notification
            
            # Phase 2: OpenProvider Domain Registration
            logger.info(f"🔄 Phase 2: Registering domain {domain_name} with OpenProvider")
            registration_result = await self._register_domain_with_provider(
                user_id, domain_name, cloudflare_result['zone_data']
            )
            
            if not registration_result.get('success'):
                return {
                    'success': False,
                    'error': f"Domain registration failed: {registration_result.get('error', 'Unknown error')}",
                    'phase': 'domain_registration',
                    'cloudflare_zone': cloudflare_result['zone_data']  # Keep zone data for cleanup
                }
            
            # Phase 3: Database Finalization
            logger.info(f"🔄 Phase 3: Finalizing registration in database for {domain_name}")
            finalization_result = await self._finalize_registration_in_database(
                order_id, user_id, domain_name, cloudflare_result, registration_result
            )
            
            if not finalization_result.get('success'):
                return {
                    'success': False,
                    'error': f"Database finalization failed: {finalization_result.get('error', 'Unknown error')}",
                    'phase': 'database_finalization',
                    'cloudflare_zone': cloudflare_result['zone_data'],
                    'registration_data': registration_result['registration_data']
                }
            
            # Success!
            return {
                'success': True,
                'order_id': order_id,
                'domain_name': domain_name,
                'cloudflare_zone': cloudflare_result['zone_data'],
                'registration_data': registration_result['registration_data'],
                'finalization_data': finalization_result['data']
            }
            
        except Exception as e:
            logger.error(f"❌ ORCHESTRATOR: Registration workflow failed for {domain_name}: {e}")
            return {
                'success': False,
                'error': str(e),
                'phase': 'workflow_exception'
            }
    
    def _generate_zone_progress_message(self, domain_name: str, payment_details: Optional[Dict]) -> str:
        """Generate zone creation progress message."""
        
        if payment_details:
            crypto_name = self.crypto_name_map.get(
                payment_details.get('crypto_currency', '').lower(), 
                payment_details.get('crypto_currency', 'Crypto').upper()
            )
            
            message = f"🚀 <b>Domain Registration Progress</b>\n\n"
            message += f"💰 Amount: <b>${payment_details.get('expected_usd', 0):.2f}</b> from {payment_details.get('received_crypto', 0):.6f} {crypto_name}\n"
            message += f"🌐 Domain: <code>{domain_name}</code>\n"
            message += f"✅ Step 1: DNS zone created\n"
            message += f"🔄 Step 2: <b>Registering with provider...</b>\n"
            message += f"⏰ <i>Final step...</i>"
        else:
            message = f"🚀 <b>Domain Registration Progress</b>\n\n"
            message += f"✅ Payment confirmed\n"
            message += f"🌐 Domain: <code>{domain_name}</code>\n"
            message += f"✅ Step 1: DNS zone created\n"
            message += f"🔄 Step 2: <b>Registering with provider...</b>\n"
            message += f"⏰ <i>Final step...</i>"
        
        return message
    
    async def _create_cloudflare_zone(self, user_id: int, domain_name: str) -> Dict[str, Any]:
        """Create Cloudflare DNS zone for the domain during registration workflow."""
        try:
            from services.cloudflare import CloudflareService
            
            cloudflare = CloudflareService()
            # Use standalone=True for new domain registrations since domain doesn't exist in database yet
            zone_result = await cloudflare.create_zone(domain_name, standalone=True)
            
            if zone_result and zone_result.get('success'):
                zone_data = zone_result['result']
                
                # Save zone to database
                nameservers = zone_data.get('name_servers', [])
                zone_saved = await save_cloudflare_zone(
                    domain_name=domain_name,
                    cf_zone_id=zone_data['id'],
                    nameservers=nameservers
                )
                
                if zone_saved:
                    logger.info(f"✅ Cloudflare zone created and saved for {domain_name}")
                    return {
                        'success': True,
                        'zone_data': zone_data
                    }
                else:
                    logger.error(f"❌ Failed to save Cloudflare zone for {domain_name}")
                    return {
                        'success': False,
                        'error': 'Failed to save zone to database'
                    }
            else:
                error_msg = zone_result.get('errors', [{}])[0].get('message', 'Unknown error') if zone_result else 'Zone creation failed'
                logger.error(f"❌ Cloudflare zone creation failed for {domain_name}: {error_msg}")
                return {
                    'success': False,
                    'error': error_msg
                }
                
        except Exception as e:
            logger.error(f"❌ Exception creating Cloudflare zone for {domain_name}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _register_domain_with_provider(
        self, 
        user_id: int, 
        domain_name: str, 
        zone_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Register domain with OpenProvider using Cloudflare nameservers."""
        try:
            from services.openprovider import OpenProviderService
            
            # Get nameservers from Cloudflare zone
            nameservers = zone_data.get('name_servers', [])
            if not nameservers:
                return {
                    'success': False,
                    'error': 'No nameservers provided by Cloudflare'
                }
            
            # Register domain with OpenProvider
            openprovider = OpenProviderService()
            # Get or create a valid shared contact handle
            contact_handle = await openprovider.get_or_create_contact_handle()
            if not contact_handle:
                logger.error(f"❌ Failed to get valid contact handle for domain registration: {domain_name}")
                return {
                    'success': False,
                    'error': 'Failed to get valid contact handle'
                }
            logger.info(f"✅ Using shared contact handle: {contact_handle}")
            registration_result = await openprovider.register_domain(
                domain_name=domain_name,
                contact_handle=contact_handle,
                nameservers=nameservers
            )
            
            if registration_result and registration_result.get('success'):
                logger.info(f"✅ Domain {domain_name} registered with OpenProvider")
                return {
                    'success': True,
                    'registration_data': registration_result
                }
            else:
                error_msg = registration_result.get('error', 'Domain registration failed') if registration_result else 'Registration failed'
                logger.error(f"❌ Domain registration failed for {domain_name}: {error_msg}")
                return {
                    'success': False,
                    'error': error_msg
                }
                
        except Exception as e:
            logger.error(f"❌ Exception registering domain {domain_name}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _finalize_registration_in_database(
        self,
        order_id: int,
        user_id: int,
        domain_name: str,
        cloudflare_result: Dict[str, Any],
        registration_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Finalize domain registration in database with new 3-table system."""
        try:
            # Create registration intent and immediately finalize it
            intent_id = await create_registration_intent(
                user_id=user_id,
                domain_name=domain_name,
                estimated_price=0.0,  # Price already handled in payment
                payment_data={
                    'order_id': order_id,
                    'currency': 'USD',
                    'status': 'completed'
                }
            )
            
            if intent_id:
                # Mark intent as completed
                await update_intent_status(intent_id, 'completed', registration_result['registration_data'])
                
                # Get provider domain ID
                provider_domain_id = registration_result['registration_data'].get('domain_id')
                if provider_domain_id:
                    domain_saved = await finalize_domain_registration(
                        intent_id=intent_id,
                        provider_domain_id=str(provider_domain_id)
                    )
                    
                    if domain_saved:
                        logger.info(f"✅ Domain registration finalized in database for {domain_name}")
                        return {
                            'success': True,
                            'data': {
                                'intent_id': intent_id,
                                'domain_saved': domain_saved,
                                'provider_domain_id': provider_domain_id
                            }
                        }
                    else:
                        return {
                            'success': False,
                            'error': 'Failed to save domain to database'
                        }
                else:
                    return {
                        'success': False,
                        'error': 'No provider domain ID returned'
                    }
            else:
                return {
                    'success': False,
                    'error': 'Failed to create registration intent'
                }
                
        except Exception as e:
            logger.error(f"❌ Exception finalizing registration for {domain_name}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _complete_registration(self, order_id: int, registration_result: Dict[str, Any]):
        """Mark order as completed in database."""
        try:
            await execute_update("""
                UPDATE domain_orders 
                SET status = 'completed',
                    updated_at = CURRENT_TIMESTAMP,
                    completed_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (order_id,))
            
            logger.info(f"✅ ORCHESTRATOR: Order {order_id} marked as completed")
            
        except Exception as e:
            logger.error(f"❌ ORCHESTRATOR: Failed to mark order {order_id} as completed: {e}")
    
    async def _fail_registration(self, order_id: int, error: str):
        """Mark order as failed in database."""
        try:
            await execute_update("""
                UPDATE domain_orders 
                SET status = 'failed',
                    updated_at = CURRENT_TIMESTAMP,
                    error_message = %s
                WHERE id = %s
            """, (error, order_id))
            
            logger.info(f"❌ ORCHESTRATOR: Order {order_id} marked as failed: {error}")
            
        except Exception as e:
            logger.error(f"❌ ORCHESTRATOR: Failed to mark order {order_id} as failed: {e}")


# ====================================================================
# GLOBAL ORCHESTRATOR INSTANCE
# ====================================================================

# Global orchestrator instance for use across the application
_orchestrator = RegistrationOrchestrator()

async def start_domain_registration(
    order_id: int,  # FIXED: Now accepts integer order ID from database
    user_id: int,
    domain_name: str,
    payment_details: Optional[Dict[str, Any]] = None,
    query_adapter: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Main entry point for domain registration processing.
    
    This replaces all direct calls to trigger_domain_registration_async.
    """
    return await _orchestrator.start_registration(
        order_id=order_id,
        user_id=user_id,
        domain_name=domain_name,
        payment_details=payment_details,
        query_adapter=query_adapter
    )

# LEGACY FUNCTION HARD-DISABLED to prevent duplicate notifications
# All registration must go through start_domain_registration() exclusively
async def trigger_domain_registration_async(query_adapter, domain_name, order, payment_details=None):
    """
    HARD-DISABLED: Legacy function to prevent duplicate notifications.
    
    ALL CALLS MUST USE start_domain_registration() instead.
    """
    logger.error("❌ CRITICAL: trigger_domain_registration_async is DISABLED - use start_domain_registration() instead")
    logger.error(f"   Attempted call for domain {domain_name}, order {order.get('id', 'unknown')}")
    
    raise RuntimeError(
        "trigger_domain_registration_async is DISABLED to prevent duplicate notifications. "
        "Use start_domain_registration() instead."
    )