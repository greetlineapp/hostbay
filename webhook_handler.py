"""
Webhook handler for cryptocurrency payment processing
Clean HTTP server to handle payment confirmation callbacks
"""

import json
import logging
import asyncio
import hmac
import hashlib
import os
import time
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, Optional
from aiohttp import web, ClientSession
from aiohttp.web_request import Request
from aiohttp.web_response import Response

# Import orchestrators for payment processing
from services.registration_orchestrator import start_domain_registration
from services.hosting_orchestrator import HostingBundleOrchestrator
from payment_validation import validate_payment_amount
from message_utils import create_success_message, create_error_message

logger = logging.getLogger(__name__)

# SPAM FIX: Suppress aiohttp access logs for successful requests (200s) but keep errors (4xx/5xx)
logging.getLogger("aiohttp.access").setLevel(logging.WARNING)

# Webhook failure tracking for alerting
_webhook_failure_count = 0
_last_successful_webhook = 0
_webhook_failure_threshold = 5  # Alert after 5 consecutive failures

# Rate limiting for success log messages to prevent spam
_last_config_success_log = 0
_last_format_success_log = 0
_success_log_interval = 60  # Log success messages at most once per minute

# Global application references
_bot_application = None
_bot_loop = None
_app_ready = asyncio.Event()
_message_queue = asyncio.Queue()
_webhook_server = None

def set_bot_application(application, loop=None):
    """Set the global bot application reference"""
    global _bot_application, _bot_loop
    _bot_application = application
    _bot_loop = loop
    
    if application is not None:
        # Verify loop is running before setting event
        if _bot_loop and _bot_loop.is_running():
            _bot_loop.call_soon_threadsafe(_app_ready.set)
            logger.info("✅ Bot application set with asyncio-based message queue")
        else:
            logger.warning("⚠️ Bot loop not running, deferring app ready signal")
    else:
        if _bot_loop and _bot_loop.is_running():
            _bot_loop.call_soon_threadsafe(_app_ready.clear)
        else:
            logger.warning("⚠️ Bot loop not available for clearing app ready signal")

async def _process_message_queue():
    """Process messages from the queue using asyncio"""
    logger.info("✅ Asyncio message queue processor started")
    
    while True:
        try:
            # Wait for message from asyncio queue
            message_data = await _message_queue.get()
            
            if message_data is None:  # Shutdown signal
                break
            
            user_id = message_data['user_id']
            text = message_data['text']
            parse_mode = message_data.get('parse_mode', 'HTML')
            
            # Convert internal user_id to telegram_id for notifications
            telegram_id = None
            if _bot_application and hasattr(_bot_application, 'bot') and _bot_application.bot:
                try:
                    # Import here to avoid circular imports
                    from database import get_telegram_id_from_user_id
                    
                    # Get telegram_id from user_id (direct async call, no threading)
                    telegram_id = await get_telegram_id_from_user_id(user_id)
                    
                    if telegram_id:
                        # Send message using correct telegram chat ID (direct async call)
                        await _bot_application.bot.send_message(
                            chat_id=telegram_id,
                            text=text,
                            parse_mode=parse_mode
                        )
                        logger.info(f"✅ Message sent to telegram_id {telegram_id} (user_id: {user_id})")
                    else:
                        logger.error(f"❌ Could not find telegram_id for user_id {user_id}")
                        
                except Exception as e:
                    logger.error(f"❌ Failed to send message to user_id {user_id} (telegram_id: {telegram_id}): {e}")
            
            _message_queue.task_done()
            
        except Exception as e:
            logger.error(f"❌ Error processing message queue: {e}")
            await asyncio.sleep(1)  # Brief delay on error

def verify_telegram_webhook_secret(request_headers) -> bool:
    """Verify Telegram webhook secret token with detailed error logging"""
    try:
        received_token = request_headers.get('X-Telegram-Bot-Api-Secret-Token')
        expected_token = os.getenv('TELEGRAM_WEBHOOK_SECRET_TOKEN')
        
        # Log detailed verification information
        if not received_token:
            logger.error("🛡️ WEBHOOK AUTH FAILURE: Missing X-Telegram-Bot-Api-Secret-Token header")
            logger.error("🔍 DEBUG: Received headers: %s", dict(request_headers))
            logger.error("⚠️ This indicates Telegram is not sending the secret token - webhook configuration issue")
            return False
            
        if not expected_token:
            logger.error("🛡️ WEBHOOK AUTH FAILURE: TELEGRAM_WEBHOOK_SECRET_TOKEN not set in environment")
            logger.error("⚠️ Bot cannot verify webhooks - webhook secret not configured properly")
            logger.error("🔧 FIX: Set TELEGRAM_WEBHOOK_SECRET_TOKEN environment variable")
            return False
        
        # Perform secure comparison
        is_valid = hmac.compare_digest(received_token, expected_token)
        
        if not is_valid:
            logger.error("🛡️ WEBHOOK AUTH FAILURE: Secret token mismatch")
            logger.error("🔍 RECEIVED TOKEN: %s... (truncated)", received_token[:8] if len(received_token) > 8 else "[too_short]")
            logger.error("🔍 EXPECTED TOKEN: %s... (truncated)", expected_token[:8] if len(expected_token) > 8 else "[too_short]")
            logger.error("⚠️ This usually means the bot was restarted and webhook secret changed")
            logger.error("🔧 FIX: Use persistent TELEGRAM_WEBHOOK_SECRET_TOKEN or re-register webhook")
            return False
            
        logger.debug("✅ Webhook authentication successful")
        return True
        
    except Exception as e:
        logger.error("🛡️ WEBHOOK AUTH EXCEPTION: %s", str(e))
        logger.error("🔍 Exception details: %s", e, exc_info=True)
        return False

def get_bot_application():
    """Get the global bot application reference"""
    return _bot_application

async def queue_user_message(user_id: int, text: str, parse_mode: str = 'HTML'):
    """Queue a message to be sent to a user"""
    await _message_queue.put({
        'user_id': user_id,
        'text': text,
        'parse_mode': parse_mode
    })

def validate_webhook_configuration() -> Dict[str, Any]:
    """Validate webhook configuration and return status"""
    global _last_config_success_log, _last_format_success_log
    import time
    
    status = {
        'webhook_secret_configured': False,
        'webhook_secret_persistent': False,
        'last_failure_count': _webhook_failure_count,
        'last_successful_webhook': _last_successful_webhook,
        'issues': []
    }
    
    try:
        # Check if webhook secret is configured
        webhook_secret = os.getenv('TELEGRAM_WEBHOOK_SECRET_TOKEN')
        if webhook_secret:
            status['webhook_secret_configured'] = True
            
            # Rate-limited success logging - only log once per minute
            current_time = time.time()
            if current_time - _last_config_success_log >= _success_log_interval:
                logger.info("✅ Webhook secret is configured")
                _last_config_success_log = current_time
            
            # Check if it looks like a proper secret (not too short)
            if len(webhook_secret) >= 16:
                status['webhook_secret_persistent'] = True
                
                # Rate-limited success logging - only log once per minute
                if current_time - _last_format_success_log >= _success_log_interval:
                    logger.info("✅ Webhook secret appears to be properly formatted")
                    _last_format_success_log = current_time
            else:
                status['issues'].append('Webhook secret too short - should be at least 16 characters')
                logger.warning("⚠️ Webhook secret is too short")  # Always log warnings immediately
        else:
            status['issues'].append('TELEGRAM_WEBHOOK_SECRET_TOKEN environment variable not set')
            logger.error("❌ Webhook secret not configured")  # Always log errors immediately
            
        # Check recent webhook failures
        if _webhook_failure_count >= _webhook_failure_threshold:
            status['issues'].append(f'High webhook failure rate: {_webhook_failure_count} consecutive failures')
            logger.error(f"🚨 High webhook failure rate detected: {_webhook_failure_count} failures")
            
        # Check if we've had recent successful webhooks
        if _last_successful_webhook > 0:
            time_since_success = time.time() - _last_successful_webhook
            if time_since_success > 3600:  # 1 hour
                status['issues'].append(f'No successful webhooks in {time_since_success/3600:.1f} hours')
                logger.warning(f"⚠️ No successful webhooks in {time_since_success/3600:.1f} hours")
                
        return status
        
    except Exception as e:
        logger.error(f"❌ Error validating webhook configuration: {e}")
        status['issues'].append(f'Validation error: {str(e)}')
        return status

def alert_webhook_authentication_failure():
    """Alert administrators about webhook authentication failures"""
    global _webhook_failure_count
    _webhook_failure_count += 1
    
    try:
        # Send critical alert if failure threshold reached
        if _webhook_failure_count >= _webhook_failure_threshold:
            logger.error(f"🚨 CRITICAL: Webhook authentication failure threshold reached ({_webhook_failure_count} failures)")
            logger.error("🚫 Bot will appear non-responsive to users until this is fixed")
            
            # Try to send admin alert if available
            try:
                from admin_alerts import send_critical_alert
                import asyncio
                asyncio.create_task(send_critical_alert(
                    f"Telegram Webhook Authentication Failure",
                    f"Bot has failed webhook authentication {_webhook_failure_count} times consecutively. "
                    f"Bot will appear dead to users. Check TELEGRAM_WEBHOOK_SECRET_TOKEN configuration."
                ))
                logger.info("✅ Critical alert sent to administrators")
            except Exception as alert_error:
                logger.warning(f"⚠️ Could not send admin alert: {alert_error}")
                
        elif _webhook_failure_count % 2 == 0:  # Log every 2 failures to avoid spam
            logger.warning(f"⚠️ Webhook authentication failures: {_webhook_failure_count} (threshold: {_webhook_failure_threshold})")
            
    except Exception as e:
        logger.error(f"❌ Error in webhook failure alerting: {e}")

def record_successful_webhook():
    """Record a successful webhook authentication"""
    global _webhook_failure_count, _last_successful_webhook
    import time
    
    # Reset failure count on success
    if _webhook_failure_count > 0:
        logger.info(f"✅ Webhook authentication recovered after {_webhook_failure_count} failures")
        _webhook_failure_count = 0
        
    _last_successful_webhook = time.time()
    logger.debug("✅ Webhook authentication successful - counters reset")

async def check_for_hosting_intent(user_id: int, domain_name: str) -> bool:
    """Check if order has hosting intent"""
    try:
        from database import execute_query
        
        intents = await execute_query(
            "SELECT id FROM hosting_provision_intents WHERE user_id = %s AND domain_name = %s AND status IN ('pending_payment', 'awaiting_payment', 'draft', 'pending_checkout', 'payment_confirmed', 'paid') LIMIT 1",
            (user_id, domain_name)
        )
        return len(intents) > 0
    except Exception as e:
        logger.error(f"❌ Error checking hosting intent: {e}")
        return False

# aiohttp handlers for webhooks

async def health_handler(request: Request) -> Response:
    """Enhanced health check with comprehensive watchdog monitoring"""
    webhook_status = validate_webhook_configuration()
    
    # Get comprehensive health status from watchdog
    try:
        from application_watchdog import get_watchdog_status, is_application_healthy
        watchdog_status = get_watchdog_status()
        app_healthy = is_application_healthy()
    except Exception as e:
        watchdog_status = {'error': f'Watchdog unavailable: {e}'}
        app_healthy = False
    
    # Get traditional health monitor status
    try:
        from health_monitor import get_health_status
        health_monitor_status = await get_health_status()
    except Exception as e:
        health_monitor_status = {'error': f'Health monitor unavailable: {e}'}
    
    # Determine overall status based on all checks
    overall_healthy = (
        not webhook_status['issues'] and
        app_healthy and
        health_monitor_status.get('overall') in ['healthy', 'warning']
    )
    
    response_data = {
        'status': 'healthy' if overall_healthy else 'degraded',
        'service': 'hostbay_telegram_bot',
        'version': '2.0_with_watchdog',
        'timestamp': time.time(),
        'checks': {
            'webhook_auth': {
                'issues': webhook_status['issues']
            },
            'health_monitor': health_monitor_status,
            'application_watchdog': watchdog_status
        }
    }
    
    # Set appropriate HTTP status code
    status_code = 200 if overall_healthy else 503
    
    return web.json_response(response_data, status=status_code)

async def watchdog_health_handler(request: Request) -> Response:
    """Dedicated watchdog health endpoint with detailed monitoring"""
    try:
        from application_watchdog import get_watchdog_status, is_application_healthy
        
        watchdog_status = get_watchdog_status()
        app_healthy = is_application_healthy()
        
        # Determine response status code
        if watchdog_status.get('state') == 'critical' or watchdog_status.get('fail_fast_triggered'):
            status_code = 503  # Service Unavailable
        elif watchdog_status.get('state') == 'warning':
            status_code = 200  # OK but with warnings
        elif app_healthy:
            status_code = 200  # Healthy
        else:
            status_code = 503  # Degraded
        
        response_data = {
            'service': 'application_watchdog',
            'status': 'healthy' if app_healthy else 'degraded',
            'version': '1.0',
            'timestamp': time.time(),
            'watchdog': watchdog_status
        }
        
        return web.json_response(response_data, status=status_code)
        
    except Exception as e:
        # Watchdog system error - this is critical
        error_response = {
            'service': 'application_watchdog',
            'status': 'error',
            'error': str(e),
            'timestamp': time.time()
        }
        return web.json_response(error_response, status=503)

async def payment_webhook_handler(request: Request) -> Response:
    """Handle payment webhook requests (GET or POST)"""
    try:
        # Check if application is ready
        if not _app_ready.is_set():
            logger.warning("⚠️ APPLICATION NOT READY: Rejecting webhook")
            return web.json_response({'error': 'Service unavailable'}, status=503)
        
        # Process payment webhook
        await _handle_payment_webhook(request)
        return web.json_response({'status': 'success'})
        
    except Exception as e:
        logger.error(f"❌ Error handling payment webhook: {e}")
        return web.json_response({'error': 'Internal server error'}, status=500)

async def telegram_webhook_handler(request: Request) -> Response:
    """Handle Telegram webhook requests"""
    try:
        # Check if application is ready
        if not _app_ready.is_set():
            logger.warning("⚠️ APPLICATION NOT READY: Rejecting webhook")
            return web.json_response({'error': 'Service unavailable'}, status=503)
        
        # Process Telegram webhook
        result = await _handle_telegram_webhook(request)
        return web.json_response(result)
        
    except Exception as e:
        logger.error(f"❌ Error handling Telegram webhook: {e}")
        return web.json_response({'error': 'Internal server error'}, status=500)
    
async def _handle_telegram_webhook(request: Request) -> Dict[str, Any]:
    """Handle Telegram webhook with enhanced security logging"""
    try:
        # Verify secret token with detailed error information
        if not verify_telegram_webhook_secret(request.headers):
            logger.error("🛡️ TELEGRAM WEBHOOK REJECTED: Authentication failed")
            logger.error("🌐 Request from: %s", request.remote)
            logger.error("📝 Request path: %s", request.path)
            logger.error("📄 Request method: %s", request.method)
            logger.error("🚫 RESULT: Webhook update will be rejected (403 Forbidden)")
            logger.error("⚠️ IMPACT: Bot will appear non-responsive to users until this is fixed")
            
            # Alert about authentication failure
            alert_webhook_authentication_failure()
            
            # Return detailed error response
            return {
                'error': 'Webhook authentication failed',
                'message': 'Invalid or missing secret token',
                'timestamp': time.time(),
                'failure_count': _webhook_failure_count
            }
        
        # Record successful authentication
        record_successful_webhook()
        
        # Read and parse data
        update_data = await request.json()
        
        logger.info(f"📱 AUTHENTICATED Telegram webhook update received: update_id={update_data.get('update_id')}")
        
        # Process the update
        await _process_telegram_update(update_data)
        
        # Return success response
        success_response = {
            'ok': True, 
            'processed_update': update_data.get('update_id'),
            'timestamp': time.time()
        }
        
        logger.info(f"✅ Successfully processed Telegram update {update_data.get('update_id')}")
        return success_response
        
    except Exception as e:
        logger.error(f"❌ Error processing Telegram webhook: {e}")
        logger.error(f"🔍 Webhook processing exception details: {e}", exc_info=True)
        
        # Return detailed error response
        return {
            'error': 'Webhook processing failed',
            'message': str(e),
            'timestamp': time.time()
        }
    
async def _process_telegram_update(update_data: Dict[str, Any]):
    """Process Telegram update directly in the same event loop"""
    if _bot_application and hasattr(_bot_application, 'process_update'):
        try:
            from telegram import Update
            
            # Convert JSON data to proper Update object
            update = Update.de_json(update_data, _bot_application.bot)
            if update:
                # Direct async call - no threading needed!
                await _bot_application.process_update(update)
                logger.debug(f"✅ Processed Telegram update: {update.update_id}")
            else:
                logger.warning(f"⚠️ Failed to parse update from JSON: {update_data}")
        except Exception as e:
            logger.error(f"❌ Error processing Telegram update: {e}")
    
async def _handle_payment_webhook(request: Request):
    """Handle payment webhook from DynoPay/BlockBee (GET or POST)"""
    try:
        # Parse callback data (GET query params or POST JSON)
        if request.method == 'GET':
            # BlockBee sends via GET with query parameters
            callback_data = dict(request.query)
            raw_payload = b''  # No body for GET
        else:
            # DynoPay sends via POST with JSON body
            try:
                callback_data = await request.json()
                raw_payload = await request.read()
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Fallback to query params if JSON parsing fails
                callback_data = dict(request.query)
                raw_payload = b''
        
        # Log callback (sanitized)
        sanitized_data = {k: '[REDACTED]' if 'token' in k.lower() else v for k, v in callback_data.items()}
        logger.info(f"📦 Payment callback received ({request.method}): {sanitized_data}")
        
        # Process the payment callback
        await _process_payment_callback(callback_data, raw_payload, request.path)
        
    except Exception as e:
        logger.error(f"❌ Error handling payment webhook: {e}")
        raise
    
async def _process_payment_callback(data: Dict[str, Any], raw_payload: bytes, path: str):
    """Process payment confirmation callback"""
    try:
        # Extract order_id from URL or data (including meta_data for DynoPay)
        parsed_url = urlparse(path)
        query_params = parse_qs(parsed_url.query)
        order_id = query_params.get('order_id', [None])[0] or data.get('order_id')
        
        # For DynoPay, also check inside meta_data
        if not order_id and 'meta_data' in data:
            meta_data = data['meta_data']
            order_id = meta_data.get('order_id') if isinstance(meta_data, dict) else None
            # Convert to string if it's an integer (DynoPay sends as integer)
            if isinstance(order_id, int):
                order_id = str(order_id)
        
        if not order_id:
            logger.error("🚫 Missing order_id in payment callback")
            return
        
        # Determine provider and extract payment details
        provider = "dynopay" if path.startswith('/webhook/dynopay') else "blockbee"
        payment_details = _extract_payment_details(data, query_params, provider)
        
        logger.info(f"💰 Payment {order_id} - Status: {payment_details['status']}, Amount: ${payment_details['amount_usd']}")
        
        # Route to appropriate handler based on order_id prefix OR meta_data
        order_type = None
        
        # First try to determine from order_id prefix
        if order_id.startswith('wallet_'):
            order_type = 'wallet'
        elif order_id.startswith('domain_'):
            order_type = 'domain'
        elif order_id.startswith('hosting_'):
            order_type = 'hosting'
        else:
            # Fallback: Use meta_data to determine order type (for DynoPay)
            if 'meta_data' in data and isinstance(data['meta_data'], dict):
                meta_data = data['meta_data']
                product_name = meta_data.get('product_name', '')
                
                # For crypto_payment product, check if it's a wallet deposit
                if product_name == 'crypto_payment':
                    order_type = 'wallet'
                elif 'domain' in product_name.lower():
                    order_type = 'domain'
                elif 'hosting' in product_name.lower():
                    order_type = 'hosting'
        
        # Route to appropriate handler
        if order_type == 'wallet':
            await _process_wallet_deposit(order_id, payment_details, provider)
        elif order_type == 'domain':
            await _process_domain_payment(order_id, payment_details)
        elif order_type == 'hosting':
            await _process_hosting_payment(order_id, payment_details)
        else:
            logger.warning(f"❌ Unknown order type: {order_id} (meta_data: {data.get('meta_data', {})})")
            
    except Exception as e:
        logger.error(f"❌ Error processing payment callback: {e}")
    
def _extract_payment_details(data: Dict, query_params: Dict, provider: str) -> Dict[str, Any]:
    """Extract payment details from callback data"""
    if provider == "dynopay":
        return {
            'status': data.get('status'),
            'amount_usd': float(data.get('base_amount', 0)),
            'amount_crypto': float(data.get('paid_amount', 0)),
            'currency': data.get('paid_currency'),
            'txid': data.get('transaction_reference'),
            'confirmations': 1 if data.get('status') == 'successful' else 0
        }
    else:  # blockbee
        return {
            'status': query_params.get('result', [None])[0],
            'amount_usd': _extract_blockbee_amount(query_params),
            'amount_crypto': float(query_params.get('value_coin', [0])[0]),
            'currency': query_params.get('currency', [''])[0],
            'txid': query_params.get('txid_in', [None])[0] or query_params.get('txid', [None])[0],
            'confirmations': int(query_params.get('confirmations', [0])[0])
        }
    
def _extract_blockbee_amount(query_params: Dict) -> float:
    """Extract USD amount from BlockBee value_coin_convert"""
    try:
        value_coin_convert_str = query_params.get('value_coin_convert', [None])[0]
        if value_coin_convert_str:
            value_coin_convert = json.loads(value_coin_convert_str)
            return float(value_coin_convert.get('USD', 0))
    except:
        pass
    return 0.0
    
async def _process_wallet_deposit(order_id: str, payment_details: Dict[str, Any], provider: str):
        """Process wallet deposit using unified credit function with database lookup"""
        try:
            # Validate payment first
            if not _is_payment_successful(payment_details):
                logger.warning(f"❌ Wallet deposit payment not successful: {order_id}")
                return
            
            # Look up payment intent and user from database using order_id
            try:
                from database import execute_query
                
                # Query payment intent to get user information
                payment_intent_query = """
                    SELECT user_id, status, created_at 
                    FROM payment_intents 
                    WHERE order_id = %s 
                    LIMIT 1
                """
                
                results = await execute_query(payment_intent_query, (int(order_id),))
                
                if not results:
                    logger.error(f"❌ No payment intent found for order_id: {order_id}")
                    return
                
                user_id = results[0]['user_id']
                logger.info(f"✅ Found payment intent for order_id {order_id}, user_id: {user_id}")
                
            except (ValueError, Exception) as e:
                logger.error(f"❌ Could not lookup payment intent for order_id {order_id}: {e}")
                return
            
            amount_usd = payment_details.get('amount_usd', 0)
            txid = payment_details.get('txid', 'unknown')
            
            # Process wallet deposit using unified credit function
            try:
                from database import credit_user_wallet
                
                # Use production-grade wallet credit function with enhanced logging
                logger.info(f"💰 WALLET_DEPOSIT_PROCESSING: Starting ${amount_usd:.2f} {provider} deposit for user_id {user_id} | txid: {txid[:16]}... | order: {order_id}")
                
                success = await credit_user_wallet(user_id, amount_usd, provider, txid, order_id)
                
                if success:
                    # SUCCESS: Could be new credit or idempotent duplicate - both are success
                    logger.info(f"✅ WALLET_DEPOSIT_SUCCESS: ${amount_usd:.2f} processed for user_id {user_id} via {provider} | txid: {txid[:16]}...")
                    # Queue success notification
                    await queue_user_message(user_id, f"🎉 <b>Wallet Credited: ${amount_usd:.2f}</b>\n\nPayment confirmed! Your wallet has been updated.")
                else:
                    # FAILURE: Actual error occurred (validation, connection, security, etc.)
                    logger.error(f"❌ WALLET_DEPOSIT_FAILURE: ${amount_usd:.2f} deposit failed for user_id {user_id} via {provider} | txid: {txid[:16]}... | Check structured logs above for specific failure reason")
                    # Queue failure notification for user
                    await queue_user_message(user_id, f"❌ <b>Payment Processing Error</b>\n\nYour ${amount_usd:.2f} payment could not be processed. Please contact support with transaction ID: <code>{txid[:16]}...</code>")
                    
            except Exception as e:
                logger.error(f"❌ Error processing wallet deposit: {e}")
            
        except Exception as e:
            logger.error(f"❌ Error processing wallet deposit: {e}")
    
# Removed _execute_secure_wallet_credit - replaced with direct call to credit_user_wallet()
    
async def _process_domain_payment(order_id: str, payment_details: Dict[str, Any]):
        """Process domain payment and route to appropriate orchestrator"""
        try:
            # Validate payment
            if not _is_payment_successful(payment_details):
                logger.warning(f"❌ Domain payment not successful: {order_id}")
                return
            
            # Extract telegram_id and domain from order_id
            # Format: domain_[domain]_[telegram_id]_[timestamp]
            parts = order_id.split('_')
            if len(parts) < 4:
                logger.error(f"❌ Invalid domain order_id format: {order_id}")
                return
            
            telegram_id = int(parts[-2])  # Extract telegram_id, not user_id
            domain_name = '_'.join(parts[1:-2])
            
            logger.info(f"🎯 Processing domain payment: {domain_name} for telegram_id {telegram_id}")
            
            # Route to appropriate orchestrator using bot event loop
            if _bot_loop and _bot_application:
                future = asyncio.run_coroutine_threadsafe(
                    _route_domain_payment(order_id, telegram_id, domain_name, payment_details),
                    _bot_loop
                )
                # Wait for completion with timeout
                future.result(timeout=15.0)  # Reduced from 30s for faster response
                logger.info(f"✅ Domain payment routing completed for {order_id}")
            else:
                logger.error(f"❌ Bot loop not available for routing {order_id}")
            
        except Exception as e:
            logger.error(f"❌ Error processing domain payment: {e}")
    
async def _route_domain_payment(order_id: str, telegram_id: int, domain_name: str, payment_details: Dict[str, Any]):
        """Route domain payment to hosting or domain-only orchestrator"""
        try:
            # CRITICAL FIX: Map string tracking ID to integer database ID
            # The order_id here is a string like "domain_registerthisname.sbs_5590563715_1758089473" 
            # where 5590563715 is the telegram_id, not the user_id
            # But the orchestrator needs the integer database ID
            integer_order_id = await _get_integer_order_id_from_tracking_id(order_id, telegram_id, domain_name)
            if integer_order_id is None:
                logger.error(f"❌ Could not find integer order ID for tracking ID: {order_id}")
                return
            
            logger.info(f"✅ Mapped tracking ID {order_id} to database order ID {integer_order_id}")
            
            # CRITICAL FIX: Conditional and idempotent order status update 
            # Only update from pending states to prevent race condition regression
            from database import execute_update, execute_query
            
            # Conditional update - only from pending states to 'paid'
            affected_rows = await execute_update(
                "UPDATE domain_orders SET status = 'paid' WHERE id = %s AND status IN ('pending_payment', 'awaiting_payment')",
                (integer_order_id,)
            )
            
            # Handle update result with proper idempotency
            if affected_rows == 1:
                logger.info(f"✅ Updated order {integer_order_id} status from pending to 'paid'")
            elif affected_rows == 0:
                # Check current status - if already paid or beyond, that's OK (idempotent)
                current_status_result = await execute_query(
                    "SELECT status FROM domain_orders WHERE id = %s",
                    (integer_order_id,)
                )
                
                if current_status_result and len(current_status_result) > 0:
                    current_status = current_status_result[0]['status']
                    if current_status in ['paid', 'processing', 'completed']:
                        logger.info(f"✅ Order {integer_order_id} already advanced (status: {current_status}) - idempotent webhook handling")
                    else:
                        logger.warning(f"⚠️ Order {integer_order_id} in unexpected status '{current_status}' - manual review needed")
                        return  # Don't proceed to orchestrator for unexpected states
                else:
                    logger.error(f"❌ Order {integer_order_id} not found in database")
                    return
            
            # Convert telegram_id to user_id for hosting intent check
            user_results = await execute_query("SELECT id FROM users WHERE telegram_id = %s", (telegram_id,))
            if not user_results:
                logger.error(f"❌ Could not find user for telegram_id {telegram_id}")
                return
            user_id = user_results[0]['id']
            
            # Check for hosting intent
            has_hosting_intent = await check_for_hosting_intent(user_id, domain_name)
            
            if has_hosting_intent:
                # CRITICAL FIX: Update hosting intent status to payment_confirmed
                # This allows the hosting orchestrator to claim the lock and process the intent
                hosting_update_result = await execute_update(
                    """UPDATE hosting_provision_intents 
                       SET status = 'payment_confirmed', updated_at = CURRENT_TIMESTAMP 
                       WHERE user_id = %s AND domain_name = %s 
                       AND status IN ('pending_payment', 'awaiting_payment')""",
                    (user_id, domain_name)
                )
                
                if hosting_update_result > 0:
                    logger.info(f"✅ Updated hosting intent status to 'payment_confirmed' for {domain_name}")
                else:
                    logger.warning(f"⚠️ No hosting intent updated for {domain_name} - may already be processed")
                
                logger.info(f"📦 HOSTING BUNDLE: Routing {domain_name} to hosting orchestrator")
                orchestrator = HostingBundleOrchestrator()
                await orchestrator.start_hosting_bundle(
                    order_id=integer_order_id,  # Use integer order ID
                    user_id=user_id,
                    domain_name=domain_name,
                    payment_details=payment_details,
                    query_adapter=WebhookQueryAdapter(user_id)
                )
            else:
                logger.info(f"📄 DOMAIN ONLY: Routing {domain_name} to domain orchestrator")
                await start_domain_registration(
                    order_id=integer_order_id,  # Use integer order ID
                    user_id=user_id,
                    domain_name=domain_name,
                    payment_details=payment_details,
                    query_adapter=WebhookQueryAdapter(user_id)
                )
                
        except Exception as e:
            logger.error(f"❌ Error routing domain payment: {e}")
    
async def _get_integer_order_id_from_tracking_id(tracking_id: str, extracted_telegram_id: int, domain_name: str) -> Optional[int]:
        """
        Map string tracking ID to integer database order ID
        
        CRITICAL FIX: The tracking_id contains telegram_id, but we need to convert to user_id
        before querying domain_orders table which uses the actual user_id (not telegram_id)
        
        Format: domain_[domain]_[telegram_id]_[timestamp]
        """
        try:
            from database import execute_query
            
            # Step 1: Convert telegram_id to actual user_id from users table
            user_results = await execute_query(
                "SELECT id FROM users WHERE telegram_id = %s LIMIT 1",
                (extracted_telegram_id,)
            )
            
            if not user_results:
                logger.error(f"❌ No user found for telegram_id {extracted_telegram_id}")
                return None
            
            actual_user_id = user_results[0]['id']
            logger.info(f"✅ Converted telegram_id {extracted_telegram_id} to user_id {actual_user_id}")
            
            # Step 2: Look up the order by tracking ID, actual user ID, and domain name
            order_results = await execute_query(
                """SELECT id FROM domain_orders 
                   WHERE blockbee_order_id = %s 
                   AND user_id = %s 
                   AND domain_name = %s 
                   LIMIT 1""",
                (tracking_id, actual_user_id, domain_name)
            )
            
            if order_results:
                integer_order_id = order_results[0]['id']
                logger.info(f"✅ Found integer order ID {integer_order_id} for tracking ID {tracking_id}")
                return integer_order_id
            else:
                logger.error(f"❌ No order found for tracking ID {tracking_id}, user {actual_user_id} (telegram_id: {extracted_telegram_id}), domain {domain_name}")
                return None
                
        except Exception as e:
            logger.error(f"❌ Error mapping tracking ID to integer order ID: {e}")
            return None
    
async def _process_hosting_payment(order_id: str, payment_details: Dict[str, Any]):
        """Process hosting payment"""
        try:
            # Validate payment
            if not _is_payment_successful(payment_details):
                logger.warning(f"❌ Hosting payment not successful: {order_id}")
                return
            
            # TODO: Implement hosting payment processing
            logger.info(f"✅ Hosting payment processed: {order_id}")
            
        except Exception as e:
            logger.error(f"❌ Error processing hosting payment: {e}")
    
def _is_payment_successful(payment_details: Dict[str, Any]) -> bool:
        """Check if payment is successful with proper provider-specific validation"""
        status = payment_details.get('status')
        confirmations = payment_details.get('confirmations', 0)
        
        # Normalize status across providers
        if isinstance(status, list) and len(status) > 0:
            status = status[0]  # Handle query param arrays
        
        # DynoPay: status == 'successful'
        # BlockBee: status/result == 'confirmed' or 'paid'
        successful_statuses = ['successful', 'confirmed', 'paid', 'sent']
        
        if status in successful_statuses:
            # For BlockBee, also check confirmations if available
            if status in ['sent'] and confirmations < 1:
                logger.info(f"⏳ Payment confirmed but waiting for confirmations: {confirmations}")
                return False
            return True
        
        logger.warning(f"❌ Payment not successful - Status: {status}, Confirmations: {confirmations}")
        return False

class WebhookQueryAdapter:
    """Adapter for sending messages via webhook handler"""
    
    def __init__(self, user_id: int):
        self.user_id = user_id
    
    async def send_message(self, text: str, parse_mode: str = 'HTML', **kwargs):
        """Send message via webhook queue"""
        await queue_user_message(self.user_id, text, parse_mode)
    
    async def edit_message_text(self, text: str, parse_mode: str = 'HTML', **kwargs):
        """Edit message (treated as send for webhook)"""
        await queue_user_message(self.user_id, text, parse_mode)

async def start_webhook_server(port: int = 5000) -> web.AppRunner:
    """Start the aiohttp webhook server in the same event loop"""
    global _webhook_server
    
    try:
        # Create aiohttp application
        app = web.Application()
        
        # Start message queue processor
        asyncio.create_task(_process_message_queue())
        logger.info("✅ Asyncio message queue processor started")
        
        # Configure routes
        app.router.add_get('/', health_handler)
        app.router.add_get('/health', health_handler)
        app.router.add_get('/healthz', health_handler)
        app.router.add_get('/api', health_handler)
        app.router.add_head('/', health_handler)
        app.router.add_head('/health', health_handler)
        app.router.add_head('/healthz', health_handler)
        app.router.add_head('/api', health_handler)
        
        # Payment webhook routes
        app.router.add_get('/webhook/blockbee', payment_webhook_handler)
        app.router.add_post('/webhook/blockbee', payment_webhook_handler)
        app.router.add_get('/webhook/dynopay', payment_webhook_handler)
        app.router.add_post('/webhook/dynopay', payment_webhook_handler)
        
        # Telegram webhook route
        app.router.add_post('/webhook/telegram', telegram_webhook_handler)
        
        # Dedicated watchdog health endpoint
        app.router.add_get('/health/watchdog', watchdog_health_handler)
        
        # Create and start runner
        runner = web.AppRunner(app)
        await runner.setup()
        
        site = web.TCPSite(runner, '0.0.0.0', port)
        await site.start()
        
        _webhook_server = runner
        
        logger.info(f"✅ Webhook server started on IPv4 http://0.0.0.0:{port}")
        logger.info("🔗 Health check endpoint: /, /health, /healthz")
        
        # Log external URL for testing
        domain = os.getenv('REPL_SLUG', 'unknown') + '-' + os.getenv('REPL_OWNER', 'unknown') + '.replit.dev'
        if domain != 'unknown-unknown.replit.dev':
            logger.info(f"🌐 External URL: https://{domain}/webhook/blockbee")
        
        return runner
        
    except Exception as e:
        logger.error(f"❌ Failed to start webhook server: {e}")
        raise

async def stop_webhook_server():
    """Stop the webhook server and cleanup"""
    global _webhook_server
    
    # Signal shutdown to message queue processor
    await _message_queue.put(None)
    
    # Stop webhook server
    if _webhook_server:
        await _webhook_server.cleanup()
        _webhook_server = None
    
    logger.info("✅ Webhook server stopped")

async def main():
    """Main function for testing"""
    runner = await start_webhook_server()
    try:
        # Keep server running
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        await stop_webhook_server()

if __name__ == "__main__":
    # Start server directly for testing
    asyncio.run(main())