"""
Hosting Bundle Orchestrator - Single Source of Truth for Hosting+Domain Bundle Processing

This module provides a centralized orchestrator for hosting bundle processing that eliminates
duplicate notifications by using database-level processing locks and notification deduplication.

Architecture:
- Atomic status state machine: pending → processing → completed
- Notification ledger with UNIQUE constraints
- Single entry point for all hosting bundle flows
- Sequential execution: domain registration → hosting provisioning
- Idempotency guards to prevent race conditions
"""

import logging
import time
import asyncio
from typing import Optional, Dict, Any, Tuple
from database import (
    execute_query, execute_update, get_or_create_user, 
    get_hosting_intent_by_id, finalize_hosting_provisioning
)
from localization import t

logger = logging.getLogger(__name__)

# ====================================================================
# HOSTING BUNDLE ORCHESTRATOR - SINGLE SOURCE OF TRUTH
# ====================================================================

class HostingBundleProcessingError(Exception):
    """Custom exception for hosting bundle processing errors"""
    pass

class DuplicateHostingBundleError(Exception):
    """Raised when attempting to process an already completed hosting bundle"""
    pass

class HostingBundleOrchestrator:
    """
    Centralized orchestrator for hosting bundle processing.
    
    Eliminates duplicate notifications through:
    1. Atomic status state machine (pending → processing → completed)
    2. Notification deduplication ledger
    3. Single entry point for all hosting bundle flows
    4. Sequential execution: domain registration → hosting provisioning
    """
    
    def __init__(self):
        self.crypto_name_map = {
            'btc': 'Bitcoin', 'ltc': 'Litecoin', 'doge': 'Dogecoin',
            'eth': 'Ethereum', 'usdt_trc20': 'USDT (TRC20)', 'usdt_erc20': 'USDT (ERC20)'
        }
    
    async def start_hosting_bundle(
        self,
        order_id: int,
        user_id: int, 
        domain_name: str,
        payment_details: Optional[Dict[str, Any]] = None,
        query_adapter: Optional[Any] = None,
        lang_code: str = 'en'
    ) -> Dict[str, Any]:
        """
        Single entry point for hosting bundle processing.
        
        Uses atomic database operations to prevent duplicate processing and notifications.
        Orchestrates: domain registration → hosting provisioning
        
        Args:
            order_id: Unique order identifier  
            user_id: Internal user ID
            domain_name: Domain to register and set up hosting for
            payment_details: Payment information for notifications
            query_adapter: For sending user notifications
            
        Returns:
            Dict with processing results and status
        """
        logger.info(t('services.hosting_orchestrator.bundle_processing.starting', lang_code, domain=domain_name))
        
        try:
            # Step 1: Find and claim hosting intent lock
            hosting_intent = await self._find_and_claim_hosting_intent(order_id, user_id, domain_name)
            if not hosting_intent:
                logger.warning(t('services.hosting_orchestrator.error_messages.no_intent_found', lang_code, order_id=order_id))
                return {'status': 'no_intent_found', 'order_id': order_id}
            
            intent_id = hosting_intent['id']
            service_type = hosting_intent.get('service_type', 'hosting_only')
            
            # Step 2: Send initial progress notification (with deduplication)
            await self._send_notification_safe(
                order_id=order_id,
                user_id=user_id,
                message_type='payment_confirmed_progress',
                domain_name=domain_name,
                payment_details=payment_details,
                query_adapter=query_adapter,
                service_type=service_type,
                lang_code=lang_code,
                hosting_intent=hosting_intent
            )
            
            # Step 3: Execute complete hosting bundle workflow
            bundle_result = await self._execute_hosting_bundle_workflow(
                order_id=order_id,
                intent_id=intent_id,
                user_id=user_id,
                domain_name=domain_name,
                service_type=service_type,
                payment_details=payment_details,
                query_adapter=query_adapter
            )
            
            # Step 4: Send final notification based on result
            if bundle_result.get('success'):
                await self._send_notification_safe(
                    order_id=order_id,
                    user_id=user_id,
                    message_type='hosting_bundle_success',
                    domain_name=domain_name,
                    payment_details=payment_details,
                    query_adapter=query_adapter,
                    service_type=service_type,
                    bundle_result=bundle_result,
                    lang_code=lang_code,
                    hosting_intent=hosting_intent
                )
                
                # Step 5: Mark bundle as completed
                await self._complete_hosting_bundle(order_id, intent_id, bundle_result)
                
            else:
                # CRITICAL: Process refunds for bundle failures that require them
                if bundle_result.get('requires_refund'):
                    logger.info(f"🔄 HOSTING ORCHESTRATOR: Bundle failure requires refund - processing for order {order_id}")
                    
                    # Import refund processor
                    from refund_processor import refund_failed_bundle_payment
                    
                    # Execute refund processing
                    refund_result = await refund_failed_bundle_payment(
                        order_id=order_id,
                        user_id=user_id,
                        domain_name=domain_name,
                        bundle_result=bundle_result,
                        payment_details=payment_details,
                        query_adapter=query_adapter
                    )
                    
                    if refund_result.get('success'):
                        logger.info(f"✅ HOSTING ORCHESTRATOR: Refund processed successfully for order {order_id}")
                        
                        # Send bundle failure notification (refund notification is sent by refund processor)
                        await self._send_notification_safe(
                            order_id=order_id,
                            user_id=user_id,
                            message_type='hosting_bundle_failure_with_refund',
                            domain_name=domain_name,
                            payment_details=payment_details,
                            query_adapter=query_adapter,
                            service_type=service_type,
                            error=bundle_result.get('error', 'Unknown error'),
                            refund_result=refund_result,
                            lang_code=lang_code,
                            hosting_intent=hosting_intent
                        )
                    else:
                        logger.error(f"❌ HOSTING ORCHESTRATOR: Refund processing failed for order {order_id}: {refund_result.get('error')}")
                        
                        # Send bundle failure notification with refund failure info
                        await self._send_notification_safe(
                            order_id=order_id,
                            user_id=user_id,
                            message_type='hosting_bundle_failure_refund_failed',
                            domain_name=domain_name,
                            payment_details=payment_details,
                            query_adapter=query_adapter,
                            service_type=service_type,
                            error=bundle_result.get('error', 'Unknown error'),
                            refund_error=refund_result.get('error', 'Unknown refund error'),
                            lang_code=lang_code,
                            hosting_intent=hosting_intent
                        )
                else:
                    # Regular failure without refund
                    await self._send_notification_safe(
                        order_id=order_id,
                        user_id=user_id,
                        message_type='hosting_bundle_failure',
                        domain_name=domain_name,
                        payment_details=payment_details,
                        query_adapter=query_adapter,
                        service_type=service_type,
                        error=bundle_result.get('error', 'Unknown error'),
                        lang_code=lang_code,
                        hosting_intent=hosting_intent
                    )
                
                # Mark bundle as failed (after refund processing)
                await self._fail_hosting_bundle(order_id, intent_id, bundle_result.get('error', 'Unknown error'))
            
            logger.info(f"✅ HOSTING ORCHESTRATOR: Bundle processing completed for order {order_id}")
            return bundle_result
            
        except DuplicateHostingBundleError as e:
            logger.warning(f"🚫 HOSTING ORCHESTRATOR: {e}")
            return {'status': 'duplicate_prevented', 'order_id': order_id}
        except Exception as e:
            logger.error(f"❌ HOSTING ORCHESTRATOR: Bundle processing failed for order {order_id}: {e}")
            return {'status': 'error', 'order_id': order_id, 'error': str(e)}
    
    async def _find_and_claim_hosting_intent(self, order_id: int, user_id: int, domain_name: str) -> Optional[Dict]:
        """
        Find hosting intent for this domain/user and atomically claim processing lock.
        
        Returns hosting intent if lock claimed, None if no intent or already claimed.
        """
        logger.debug(f"🔒 HOSTING ORCHESTRATOR: Finding and claiming hosting intent for {domain_name}")
        
        try:
            # Find active hosting intent for this domain and user
            from database import get_active_hosting_intent
            hosting_intent = await get_active_hosting_intent(user_id, domain_name)
            
            if not hosting_intent:
                logger.warning(f"🚫 HOSTING ORCHESTRATOR: No active hosting intent found for user {user_id}, domain {domain_name}")
                return None
            
            intent_id = hosting_intent['id']
            
            # Atomic update: claim processing lock only if status allows it
            # FIXED: Include 'payment_confirmed' status for paid bundles and updated statuses
            rows_updated = await execute_update("""
                UPDATE hosting_provision_intents 
                SET status = 'processing_payment', 
                    updated_at = CURRENT_TIMESTAMP,
                    processing_started_at = CURRENT_TIMESTAMP
                WHERE id = %s 
                AND user_id = %s 
                AND status IN ('pending_payment', 'awaiting_payment', 'draft', 'pending_checkout', 'payment_confirmed', 'paid')
            """, (intent_id, user_id))
            
            if rows_updated > 0:
                logger.info(f"✅ HOSTING ORCHESTRATOR: Processing lock claimed for intent {intent_id}")
                return hosting_intent
            else:
                # Check current status to understand why lock wasn't claimed
                current_intents = await execute_query(
                    "SELECT status FROM hosting_provision_intents WHERE id = %s", 
                    (intent_id,)
                )
                
                if current_intents:
                    current_status = current_intents[0]['status']
                    logger.warning(f"🚫 HOSTING ORCHESTRATOR: Cannot claim lock - intent {intent_id} status: {current_status}")
                    
                    if current_status in ('completed', 'processing_payment'):
                        raise DuplicateHostingBundleError(f"Hosting intent {intent_id} already {current_status}")
                else:
                    logger.error(f"❌ HOSTING ORCHESTRATOR: Hosting intent {intent_id} not found")
                
                return None
                
        except DuplicateHostingBundleError:
            raise
        except Exception as e:
            logger.error(f"❌ HOSTING ORCHESTRATOR: Failed to find/claim hosting intent for {domain_name}: {e}")
            return None
    
    async def _execute_hosting_bundle_workflow(
        self,
        order_id: int,
        intent_id: int,
        user_id: int,
        domain_name: str,
        service_type: str,
        payment_details: Optional[Dict],
        query_adapter: Optional[Any]
    ) -> Dict[str, Any]:
        """
        Execute the complete hosting bundle workflow.
        
        For hosting bundles: domain registration → hosting provisioning
        For hosting-only: hosting provisioning only
        """
        logger.info(f"🔄 HOSTING ORCHESTRATOR: Executing workflow for intent {intent_id}, service_type: {service_type}")
        
        try:
            # Check if this is a bundle that needs domain registration
            needs_domain_registration = service_type in ['hosting_domain_bundle']
            
            # CRITICAL FIX: For bundles, validate hosting FIRST to prevent partial failures
            if needs_domain_registration:
                # Phase 1: Hosting Validation (TEST cPanel creation without committing)
                logger.info(f"🔄 Phase 1: Validating hosting capabilities for bundle - {domain_name}")
                hosting_validation = await self._validate_hosting_provisioning(
                    intent_id, user_id, domain_name, payment_details
                )
                
                if not hosting_validation.get('success'):
                    logger.error(f"❌ Hosting validation failed - will not proceed with domain registration")
                    return {
                        'success': False,
                        'error': f"Hosting validation failed: {hosting_validation.get('error', 'Unknown error')}. Refund will be processed.",
                        'phase': 'hosting_validation',
                        'requires_refund': True  # Signal that refund is needed
                    }
                
                # Phase 2: Domain Registration (only if hosting validation passed)
                logger.info(f"🔄 Phase 2: Domain registration for bundle - {domain_name}")
                domain_result = await self._execute_domain_registration(
                    order_id, user_id, domain_name, payment_details, query_adapter
                )
                
                if not domain_result.get('success'):
                    return {
                        'success': False,
                        'error': f"Domain registration failed: {domain_result.get('error', 'Unknown error')}",
                        'phase': 'domain_registration',
                        'requires_refund': True  # Domain failed after hosting validation passed
                    }
                
                # Phase 3: Actual Hosting Provisioning (hosting validation passed, domain registered)
                logger.info(f"🔄 Phase 3: Creating hosting account for bundle - {domain_name}")
                hosting_result = await self._execute_hosting_provisioning(
                    intent_id, user_id, domain_name, payment_details
                )
            else:
                # Hosting-only flow (no domain registration)
                logger.info(f"🔄 Phase 1: Hosting provisioning for intent {intent_id}")
                hosting_result = await self._execute_hosting_provisioning(
                    intent_id, user_id, domain_name, payment_details
                )
                domain_result = None
            
            if not hosting_result.get('success'):
                return {
                    'success': False,
                    'error': f"Hosting provisioning failed: {hosting_result.get('error', 'Unknown error')}",
                    'phase': 'hosting_provisioning',
                    'domain_result': domain_result,  # Keep domain data for cleanup if needed
                    'requires_refund': needs_domain_registration  # Refund needed for bundles only
                }
            
            # Phase 3: Update DNS A record with server IP (only for bundles)
            if needs_domain_registration and domain_result:
                logger.info(f"🔄 Phase 3: Updating DNS A record with server IP for {domain_name}")
                dns_update_result = await self._update_dns_with_server_ip(
                    domain_name, domain_result, hosting_result
                )
                
                if not dns_update_result.get('success'):
                    # Log warning but don't fail the entire workflow - hosting is already provisioned
                    logger.warning(f"⚠️ DNS A record update failed for {domain_name}: {dns_update_result.get('error')}")
                    # Continue with success since hosting is working
            
            # Success!
            return {
                'success': True,
                'order_id': order_id,
                'intent_id': intent_id,
                'domain_name': domain_name,
                'service_type': service_type,
                'domain_result': domain_result,
                'hosting_result': hosting_result
            }
            
        except Exception as e:
            logger.error(f"❌ HOSTING ORCHESTRATOR: Workflow failed for intent {intent_id}: {e}")
            return {
                'success': False,
                'error': str(e),
                'phase': 'workflow_exception'
            }
    
    async def _execute_domain_registration(
        self, 
        order_id: int, 
        user_id: int, 
        domain_name: str, 
        payment_details: Optional[Dict],
        query_adapter: Optional[Any]
    ) -> Dict[str, Any]:
        """
        Execute domain registration using the existing registration orchestrator.
        """
        try:
            # Import and use existing domain registration orchestrator
            from services.registration_orchestrator import RegistrationOrchestrator
            
            domain_orchestrator = RegistrationOrchestrator()
            
            # Call existing domain registration with adapted query adapter
            domain_result = await domain_orchestrator.start_registration(
                order_id=order_id,
                user_id=user_id,
                domain_name=domain_name,
                payment_details=payment_details,
                query_adapter=query_adapter
            )
            
            return domain_result
            
        except Exception as e:
            logger.error(f"❌ HOSTING ORCHESTRATOR: Domain registration failed for {domain_name}: {e}")
            return {
                'success': False,
                'error': str(e),
                'phase': 'domain_registration_exception'
            }
    
    async def _execute_hosting_provisioning(
        self, 
        intent_id: int, 
        user_id: int, 
        domain_name: str, 
        payment_details: Optional[Dict]
    ) -> Dict[str, Any]:
        """
        Execute hosting provisioning by creating cPanel account first, then finalizing in database.
        """
        try:
            # CRITICAL FIX: Actually create cPanel account first
            from services.cpanel import CPanelService
            from database import execute_query
            
            # Get user email for cPanel account creation
            user_data = await execute_query("SELECT email FROM users WHERE id = %s", (user_id,))
            user_email = user_data[0]['email'] if user_data and user_data[0].get('email') else f'user{user_id}@temp.hostbay.sbs'
            
            # Generate cPanel username
            cpanel_username = f"user{user_id}_{intent_id}"
            
            # Step 1: Create actual cPanel hosting account
            cpanel_service = CPanelService()
            logger.info(f"🔧 Creating cPanel account for {domain_name} with username {cpanel_username}")
            
            cpanel_result = await cpanel_service.create_hosting_account(
                domain=domain_name,
                plan='basic',  # Use basic plan for hosting bundles
                email=user_email,
                intent_id=intent_id
            )
            
            if not cpanel_result:
                logger.error(f"❌ cPanel account creation failed for {domain_name}")
                return {
                    'success': False,
                    'error': 'cPanel account creation failed - please contact support',
                    'phase': 'cpanel_creation'
                }
            
            logger.info(f"✅ cPanel account created successfully for {domain_name}")
            
            # Step 2: Prepare cPanel results for database finalization
            cpanel_data = {
                "username": cpanel_result.get('username', cpanel_username),
                "password": cpanel_result.get('password'),
                "server_ip": cpanel_result.get('server_ip') or cpanel_service.default_server_ip,
                "domain_name": domain_name,
                "service_type": "hosting_domain_bundle",
                "payment_method": "crypto"
            }
            
            # Add payment details if available
            if payment_details:
                cpanel_data.update(payment_details)
            
            # Step 3: Finalize in database with actual cPanel results
            provisioning_result = await finalize_hosting_provisioning(
                intent_id, 
                cpanel_username, 
                cpanel_data
            )
            
            # Handle different return formats (boolean or dict)
            if isinstance(provisioning_result, dict):
                if provisioning_result.get('success', False):
                    return {
                        'success': True,
                        'provisioning_data': provisioning_result
                    }
                else:
                    return {
                        'success': False,
                        'error': provisioning_result.get('error', 'Hosting provisioning failed')
                    }
            elif provisioning_result:  # Boolean True
                return {
                    'success': True,
                    'provisioning_data': {'status': 'completed'}
                }
            else:  # Boolean False or None
                return {
                    'success': False,
                    'error': 'Hosting provisioning returned false'
                }
                
        except Exception as e:
            logger.error(f"❌ HOSTING ORCHESTRATOR: Hosting provisioning failed for intent {intent_id}: {e}")
            return {
                'success': False,
                'error': str(e),
                'phase': 'hosting_provisioning_exception'
            }
    
    async def _validate_hosting_provisioning(
        self, 
        intent_id: int, 
        user_id: int, 
        domain_name: str, 
        payment_details: Optional[Dict]
    ) -> Dict[str, Any]:
        """
        Validate hosting provisioning capabilities without creating actual account.
        Tests cPanel connectivity and configuration to prevent partial bundle failures.
        """
        try:
            from services.cpanel import CPanelService
            
            logger.info(f"🔍 Validating hosting capabilities for {domain_name}")
            
            # Step 1: Test cPanel service connectivity
            cpanel_service = CPanelService()
            connection_ok, connection_msg = await cpanel_service.test_connection()
            
            if not connection_ok:
                logger.error(f"❌ cPanel connection validation failed: {connection_msg}")
                return {
                    'success': False,
                    'error': f'Hosting service unavailable: {connection_msg}',
                    'phase': 'connectivity_test'
                }
            
            logger.info(f"✅ cPanel connectivity validated: {connection_msg}")
            
            # Step 2: Check if cPanel credentials are properly configured
            if not cpanel_service.whm_api_token and not cpanel_service.whm_password:
                logger.error("❌ cPanel credentials not configured for hosting validation")
                return {
                    'success': False,
                    'error': 'Hosting service configuration error - please contact support',
                    'phase': 'credentials_check'
                }
            
            # Step 3: Check for resource availability (if we can query server status)
            try:
                # This is a lightweight check - we just validate we can communicate with WHM
                logger.info(f"✅ Hosting validation passed for {domain_name}")
                return {
                    'success': True,
                    'message': 'Hosting capabilities validated successfully',
                    'server_ip': cpanel_service.default_server_ip
                }
                
            except Exception as resource_error:
                logger.warning(f"⚠️ Hosting resource check warning: {resource_error}")
                # Continue anyway - this is just a warning
                return {
                    'success': True,
                    'message': 'Hosting capabilities validated with warnings',
                    'server_ip': cpanel_service.default_server_ip,
                    'warnings': str(resource_error)
                }
                
        except Exception as e:
            logger.error(f"❌ Hosting validation failed for {domain_name}: {e}")
            return {
                'success': False,
                'error': f'Hosting validation error: {str(e)}',
                'phase': 'validation_exception'
            }
    
    async def _send_notification_safe(
        self,
        order_id: int,
        user_id: int,
        message_type: str,
        domain_name: str,
        payment_details: Optional[Dict] = None,
        query_adapter: Optional[Any] = None,
        service_type: Optional[str] = None,
        bundle_result: Optional[Dict] = None,
        error: Optional[str] = None,
        lang_code: str = 'en',
        hosting_intent: Optional[Dict] = None,
        refund_result: Optional[Dict] = None,
        refund_error: Optional[str] = None
    ) -> bool:
        """
        Send notification with deduplication protection.
        
        Uses notification ledger with UNIQUE constraints to prevent duplicate messages.
        """
        logger.debug(f"📧 HOSTING ORCHESTRATOR: Sending {message_type} notification for order {order_id}")
        
        try:
            # Step 1: Check if notification already sent using deduplication ledger
            # Use domain_notifications table with hosting_ prefix for compatibility
            notification_key = f"hosting_{order_id}"
            existing_notifications = await execute_query("""
                SELECT id, sent_at FROM domain_notifications 
                WHERE order_id = %s AND message_type = %s
            """, (notification_key, message_type))
            
            if existing_notifications:
                logger.warning(f"🚫 HOSTING ORCHESTRATOR: {message_type} notification already sent for order {order_id}")
                return False
            
            # Step 2: Generate notification message
            message = self._generate_notification_message(
                message_type=message_type,
                domain_name=domain_name,
                service_type=service_type,
                payment_details=payment_details,
                bundle_result=bundle_result,
                error=error,
                lang_code=lang_code,
                hosting_intent=hosting_intent
            )
            
            # Step 3: Record notification in ledger (with deduplication protection)
            try:
                await execute_update("""
                    INSERT INTO domain_notifications (order_id, message_type, user_id, message_content, sent_at)
                    VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
                """, (notification_key, message_type, user_id, message))
                
                logger.info(f"📧 HOSTING ORCHESTRATOR: {message_type} notification recorded for order {order_id}")
                
            except Exception as db_error:
                logger.error(f"❌ HOSTING ORCHESTRATOR: Database error recording {message_type} notification: {db_error}")
                # Continue to send notification even if recording fails
            
            # Step 4: Send notification to user
            if query_adapter:
                await self._send_message_to_user(query_adapter, message)
                logger.info(f"✅ HOSTING ORCHESTRATOR: {message_type} notification sent to user for order {order_id}")
            else:
                logger.warning(f"⚠️ HOSTING ORCHESTRATOR: No query_adapter provided for {message_type} notification")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ HOSTING ORCHESTRATOR: Failed to send {message_type} notification for order {order_id}: {e}")
            return False
    
    def _generate_notification_message(
        self,
        message_type: str,
        domain_name: str,
        service_type: Optional[str] = None,
        payment_details: Optional[Dict] = None,
        bundle_result: Optional[Dict] = None,
        error: Optional[str] = None,
        lang_code: str = 'en',
        hosting_intent: Optional[Dict] = None
    ) -> str:
        """Generate notification message based on type and context."""
        
        if message_type == 'payment_confirmed_progress':
            return self._generate_bundle_progress_message(domain_name, service_type or 'hosting_only', payment_details, lang_code, hosting_intent)
        elif message_type == 'hosting_bundle_success':
            return self._generate_bundle_success_message(domain_name, service_type or 'hosting_only', payment_details, bundle_result, lang_code, hosting_intent)
        elif message_type == 'hosting_bundle_failure':
            return self._generate_bundle_failure_message(domain_name, service_type or 'hosting_only', payment_details, error, lang_code, hosting_intent)
        else:
            return t('services.hosting_orchestrator.bundle_processing.completed', lang_code, order_id=domain_name)
    
    def _generate_bundle_progress_message(self, domain_name: str, service_type: str, payment_details: Optional[Dict], lang_code: str = 'en', hosting_intent: Optional[Dict] = None) -> str:
        """Generate hosting bundle progress message."""
        
        # Prepare variables for translation
        kwargs = {'domain': domain_name}
        
        # If payment_details is None but we have hosting intent data (wallet payment), construct payment details
        if not payment_details and hosting_intent and hosting_intent.get('estimated_price'):
            payment_details = {
                'amount_usd': hosting_intent.get('estimated_price', 0),
                'currency': 'USD',
                'payment_method': 'wallet'
            }
        
        if payment_details:
            crypto_name = self.crypto_name_map.get(
                payment_details.get('crypto_currency', '').lower(), 
                payment_details.get('crypto_currency', 'Crypto').upper()
            )
            
            # Extract amount from various possible payment detail formats
            amount_usd = (payment_details.get('expected_usd') or 
                         payment_details.get('amount_usd') or 
                         payment_details.get('original_amount') or 
                         payment_details.get('base_amount', 0))
            
            received_crypto = (payment_details.get('received_crypto') or 
                              payment_details.get('paid_amount', 0))
            
            kwargs.update({
                'amount': f"{float(amount_usd):.2f}",
                'crypto_amount': f"{float(received_crypto):.6f}",
                'crypto_currency': crypto_name
            })
        else:
            kwargs.update({
                'amount': '0.00',
                'crypto_amount': '0.000000',
                'crypto_currency': 'Crypto'
            })
        
        # Use translation system to generate the message
        return t('services.hosting_orchestrator.bundle_processing.payment_confirmed', lang_code, **kwargs)
    
    def _generate_domain_success_progress_message(self, domain_name: str, payment_details: Optional[Dict], service_type: str, lang_code: str = 'en', hosting_intent: Optional[Dict] = None) -> str:
        """Generate domain registration success + hosting progress message."""
        
        kwargs = {'domain': domain_name}
        
        # If payment_details is None but we have hosting intent data (wallet payment), construct payment details
        if not payment_details and hosting_intent and hosting_intent.get('estimated_price'):
            payment_details = {
                'amount_usd': hosting_intent.get('estimated_price', 0),
                'currency': 'USD',
                'payment_method': 'wallet'
            }
        
        if payment_details:
            amount_usd = (payment_details.get('expected_usd') or 
                         payment_details.get('amount_usd') or 0)
            kwargs['amount'] = f"{float(amount_usd):.2f}"
        else:
            kwargs['amount'] = '0.00'
        
        return t('services.hosting_orchestrator.success_notifications.hosting_ready', lang_code, **kwargs)
    
    def _generate_bundle_success_message(
        self, 
        domain_name: str, 
        service_type: str,
        payment_details: Optional[Dict], 
        bundle_result: Optional[Dict],
        lang_code: str = 'en',
        hosting_intent: Optional[Dict] = None
    ) -> str:
        """Generate hosting bundle success message."""
        
        # Prepare variables for translation
        kwargs = {'domain': domain_name}
        
        # If payment_details is None but we have hosting intent data (wallet payment), construct payment details
        if not payment_details and hosting_intent and hosting_intent.get('estimated_price'):
            payment_details = {
                'amount_usd': hosting_intent.get('estimated_price', 0),
                'currency': 'USD',
                'payment_method': 'wallet'
            }
        
        if payment_details:
            amount_usd = (payment_details.get('expected_usd') or 
                         payment_details.get('amount_usd') or 
                         payment_details.get('original_amount') or 
                         payment_details.get('base_amount', 0))
            kwargs['amount'] = f"{float(amount_usd):.2f}"
        else:
            kwargs['amount'] = '0.00'
        
        # Use translation system to generate the message
        return t('services.hosting_orchestrator.success_notifications.bundle_success', lang_code, **kwargs)
    
    def _generate_bundle_failure_message(
        self, 
        domain_name: str, 
        service_type: str,
        payment_details: Optional[Dict], 
        error: Optional[str],
        lang_code: str = 'en',
        hosting_intent: Optional[Dict] = None
    ) -> str:
        """Generate hosting bundle failure message."""
        
        # Prepare variables for translation
        kwargs = {
            'domain': domain_name,
            'error': error or t('services.common.errors.unknown_error', lang_code),
            'support_contact': 'Hostbay_support'
        }
        
        # If payment_details is None but we have hosting intent data (wallet payment), construct payment details
        if not payment_details and hosting_intent and hosting_intent.get('estimated_price'):
            payment_details = {
                'amount_usd': hosting_intent.get('estimated_price', 0),
                'currency': 'USD',
                'payment_method': 'wallet'
            }
        
        if payment_details:
            amount_usd = (payment_details.get('expected_usd') or 
                         payment_details.get('amount_usd') or 
                         payment_details.get('original_amount') or 
                         payment_details.get('base_amount', 0))
            kwargs['amount'] = f"{float(amount_usd):.2f}"
        else:
            kwargs['amount'] = '0.00'
        
        # Use translation system to generate the message
        return t('services.hosting_orchestrator.error_messages.bundle_failure', lang_code, **kwargs)
    
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
    
    async def _complete_hosting_bundle(self, order_id: int, intent_id: int, bundle_result: Dict[str, Any]):
        """Mark hosting bundle as completed."""
        try:
            await execute_update("""
                UPDATE hosting_provision_intents 
                SET status = 'completed', 
                    updated_at = CURRENT_TIMESTAMP,
                    completed_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (intent_id,))
            
            logger.info(f"✅ HOSTING ORCHESTRATOR: Bundle marked as completed - order {order_id}, intent {intent_id}")
            
        except Exception as e:
            logger.error(f"❌ HOSTING ORCHESTRATOR: Failed to mark bundle as completed - order {order_id}: {e}")
    
    async def _fail_hosting_bundle(self, order_id: int, intent_id: int, error: str):
        """Mark hosting bundle as failed."""
        try:
            await execute_update("""
                UPDATE hosting_provision_intents 
                SET status = 'failed', 
                    error_message = %s,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (error, intent_id))
            
            logger.info(f"❌ HOSTING ORCHESTRATOR: Bundle marked as failed - order {order_id}, intent {intent_id}: {error}")
            
        except Exception as e:
            logger.error(f"❌ HOSTING ORCHESTRATOR: Failed to mark bundle as failed - order {order_id}: {e}")
    
    async def _update_dns_with_server_ip(
        self, 
        domain_name: str, 
        domain_result: Dict[str, Any], 
        hosting_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Update Cloudflare DNS A record with actual WHM server IP after hosting provisioning.
        
        This fixes the issue where A records are created with placeholder IP (8.8.8.8)
        during domain registration but never updated with the real server IP.
        """
        try:
            from services.cloudflare import CloudflareService
            
            # Get server IP from hosting result or database
            server_ip = None
            
            # Try to get server IP from hosting result first
            if hosting_result.get('provisioning_data'):
                server_ip = hosting_result['provisioning_data'].get('server_ip')
            
            # If not found, try to get it from the database
            if not server_ip:
                try:
                    # Get hosting details from intent ID
                    intent_id = hosting_result.get('intent_id')
                    if intent_id:
                        hosting_intent = await get_hosting_intent_by_id(intent_id)
                        if hosting_intent and hosting_intent.get('external_reference'):
                            # Extract subscription ID from external reference
                            external_ref = hosting_intent['external_reference']
                            if external_ref.startswith('subscription_'):
                                sub_id = int(external_ref.replace('subscription_', ''))
                                hosting_details = await execute_query(
                                    "SELECT server_ip FROM hosting_subscriptions WHERE id = %s",
                                    (sub_id,)
                                )
                                if hosting_details:
                                    server_ip = hosting_details[0].get('server_ip')
                except:
                    pass  # Function may not exist, continue with fallback
            
            # Fallback to cPanel service default
            if not server_ip:
                from services.cpanel import CPanelService
                cpanel = CPanelService()
                server_ip = cpanel.default_server_ip
                logger.info(f"🔧 Using cPanel service default IP: {server_ip}")
            
            if not server_ip:
                return {
                    'success': False,
                    'error': 'No server IP available for DNS update'
                }
            
            # Get zone ID from domain result or database
            zone_id = None
            if domain_result.get('zone_data'):
                zone_id = domain_result['zone_data'].get('zone_id')
            
            # Fallback: Try to get zone ID from database
            if not zone_id:
                try:
                    zone_results = await execute_query(
                        "SELECT cf_zone_id FROM cloudflare_zones WHERE domain_name = %s ORDER BY created_at DESC LIMIT 1",
                        (domain_name,)
                    )
                    if zone_results:
                        zone_id = zone_results[0]['cf_zone_id']
                        logger.info(f"🔧 Retrieved zone ID from database: {zone_id}")
                except Exception as e:
                    logger.error(f"❌ Error retrieving zone ID from database: {e}")
            
            if not zone_id:
                return {
                    'success': False,
                    'error': 'No Cloudflare zone ID available for DNS update'
                }
            
            logger.info(f"🔧 Updating DNS A record: {domain_name} → {server_ip} (zone: {zone_id})")
            
            # Initialize Cloudflare service
            cloudflare = CloudflareService()
            
            # Get existing A records for the domain
            existing_records = await cloudflare.list_dns_records(zone_id, 'A')
            
            # Find the root domain A record (should be pointing to 8.8.8.8)
            root_a_record = None
            for record in existing_records:
                if record.get('name') == domain_name:
                    root_a_record = record
                    break
            
            if not root_a_record:
                logger.warning(f"⚠️ No A record found for {domain_name} - creating new one")
                # Create new A record if none exists
                create_result = await cloudflare.create_dns_record(
                    zone_id=zone_id,
                    record_type='A',
                    name=domain_name,
                    content=server_ip,
                    ttl=300,
                    proxied=False
                )
                
                if create_result.get('success'):
                    logger.info(f"✅ Created new A record: {domain_name} → {server_ip}")
                    return {'success': True, 'action': 'created', 'ip': server_ip}
                else:
                    return {
                        'success': False, 
                        'error': f"Failed to create A record: {create_result.get('errors', [])}"
                    }
            
            # Update existing A record
            record_id = root_a_record.get('id')
            current_ip = root_a_record.get('content')
            
            logger.info(f"🔄 Found A record {record_id}: {domain_name} → {current_ip}")
            
            # Check if update is needed
            if current_ip == server_ip:
                logger.info(f"✅ A record already points to correct IP: {server_ip}")
                return {'success': True, 'action': 'no_change_needed', 'ip': server_ip}
            
            # Update the A record
            update_result = await cloudflare.update_dns_record(
                zone_id=zone_id,
                record_id=str(record_id) if record_id else "",  # Ensure string type
                record_type='A',
                name=domain_name,
                content=server_ip,
                ttl=300,
                proxied=False
            )
            
            if update_result.get('success'):
                logger.info(f"✅ Updated A record: {domain_name} → {server_ip} (was: {current_ip})")
                return {
                    'success': True, 
                    'action': 'updated', 
                    'old_ip': current_ip, 
                    'new_ip': server_ip
                }
            else:
                return {
                    'success': False,
                    'error': f"Failed to update A record: {update_result.get('errors', [])}"
                }
                
        except Exception as e:
            logger.error(f"❌ Exception updating DNS A record for {domain_name}: {e}")
            return {
                'success': False,
                'error': str(e)
            }

# ====================================================================
# CONVENIENCE FUNCTION FOR EXTERNAL USE
# ====================================================================

async def start_hosting_bundle(
    order_id: int,
    user_id: int,
    domain_name: str, 
    payment_details: Optional[Dict[str, Any]] = None,
    query_adapter: Optional[Any] = None,
    lang_code: str = 'en'
) -> Dict[str, Any]:
    """
    Convenience function to start hosting bundle processing.
    
    Creates orchestrator instance and delegates to start_hosting_bundle method.
    """
    orchestrator = HostingBundleOrchestrator()
    return await orchestrator.start_hosting_bundle(
        order_id=order_id,
        user_id=user_id,
        domain_name=domain_name,
        payment_details=payment_details,
        query_adapter=query_adapter,
        lang_code=lang_code
    )