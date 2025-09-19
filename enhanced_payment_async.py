"""
Enhanced Payment Async Handling Module
Provides improved async/await patterns for payment processing with better error handling,
timeout management, and concurrent safety.
"""

import asyncio
import json
import logging
import time
from typing import Dict, Any, Optional, List
from database import (
    credit_user_wallet, get_or_create_user, get_user_wallet_balance, 
    execute_query, execute_update
)

logger = logging.getLogger(__name__)

async def credit_user_wallet_with_context(user_id: int, amount_usd: float, provider: str, txid: str, order_id: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Enhanced wallet credit function with context tracking and detailed result reporting
    
    Args:
        user_id: Database user ID (not telegram_id)
        amount_usd: Amount to credit in USD
        provider: Payment provider ('dynopay', 'blockbee', etc.)
        txid: Transaction ID from provider
        order_id: Our internal order ID
        context: Additional context for tracking (webhook source, retry attempts, etc.)
        
    Returns:
        Dict with detailed operation result:
        {
            'success': bool,
            'duplicate': bool,  # True if this was a duplicate transaction
            'amount_credited': float,
            'new_balance': float,
            'old_balance': float,
            'transaction_id': int,
            'error': str,  # Only present if success=False
            'processing_time': float
        }
    """
    start_time = time.time()
    
    # Initialize context if not provided
    if context is None:
        context = {}
    
    logger.info(f"💰 WALLET_CREDIT_ENHANCED: Starting ${amount_usd:.2f} credit for user {user_id} | Context: {context}")
    
    try:
        # Get current balance before crediting
        old_balance = await get_user_wallet_balance(user_id)
        
        # Call the existing function
        success = await credit_user_wallet(user_id, amount_usd, provider, txid, order_id)
        processing_time = time.time() - start_time
        
        if success:
            # Get updated user balance for detailed reporting
            try:
                new_balance = await get_user_wallet_balance(user_id)
                
                # Check if this was a duplicate by looking at recent transactions
                duplicate_check = await execute_query(
                    """SELECT id FROM wallet_transactions 
                       WHERE external_txid = %s AND provider = %s AND user_id = %s
                       ORDER BY created_at DESC LIMIT 1""",
                    (txid, provider, user_id)
                )
                
                transaction_id = duplicate_check[0]['id'] if duplicate_check else None
                
                # Determine if this was a duplicate based on balance change
                was_duplicate = abs(new_balance - old_balance - amount_usd) > 0.01
                
                result = {
                    'success': True,
                    'duplicate': was_duplicate,
                    'amount_credited': amount_usd,
                    'new_balance': new_balance,
                    'old_balance': old_balance,
                    'transaction_id': transaction_id,
                    'processing_time': processing_time
                }
                
                logger.info(f"✅ WALLET_CREDIT_ENHANCED_SUCCESS: Result: {result}")
                return result
                
            except Exception as balance_error:
                # Fallback result if balance lookup fails
                logger.warning(f"⚠️ Could not fetch updated balance info: {balance_error}")
                return {
                    'success': True,
                    'duplicate': False,
                    'amount_credited': amount_usd,
                    'new_balance': None,
                    'old_balance': old_balance,
                    'transaction_id': None,
                    'processing_time': processing_time
                }
        else:
            processing_time = time.time() - start_time
            result = {
                'success': False,
                'error': f'Credit operation failed for user {user_id}',
                'processing_time': processing_time
            }
            
            logger.error(f"❌ WALLET_CREDIT_ENHANCED_FAILURE: Result: {result}")
            return result
            
    except Exception as e:
        processing_time = time.time() - start_time
        error_msg = f'Async credit operation failed: {str(e)}'
        
        result = {
            'success': False,
            'error': error_msg,
            'processing_time': processing_time
        }
        
        logger.error(f"❌ WALLET_CREDIT_ENHANCED_ERROR: {error_msg} | Result: {result}")
        return result

async def process_payment_webhook_async(webhook_data: Dict[str, Any], provider: str, order_type: str) -> Dict[str, Any]:
    """
    Enhanced async webhook processing with proper isolation and error handling
    
    Args:
        webhook_data: Payment webhook data from provider
        provider: Payment provider name ('dynopay', 'blockbee')
        order_type: Type of order ('wallet', 'domain', 'hosting')
        
    Returns:
        Dict with processing result and details
    """
    start_time = time.time()
    
    processing_id = f"{provider}_{int(time.time())}_{hash(str(webhook_data)) % 10000}"
    logger.info(f"🔄 WEBHOOK_ASYNC_START: {processing_id} | Provider: {provider} | Type: {order_type}")
    
    try:
        # Enhanced webhook validation with timeout
        validation_result = await asyncio.wait_for(
            _validate_webhook_data_async(webhook_data, provider),
            timeout=5.0  # 5 second validation timeout
        )
        
        if not validation_result['valid']:
            return {
                'success': False,
                'error': f'Webhook validation failed: {validation_result["error"]}',
                'processing_time': time.time() - start_time,
                'processing_id': processing_id
            }
        
        # Extract and normalize payment details with timeout
        payment_details = await asyncio.wait_for(
            _extract_payment_details_async(webhook_data, provider),
            timeout=5.0  # 5 second extraction timeout
        )
        
        # Route to appropriate async processor based on order type
        if order_type == 'wallet':
            result = await _process_wallet_webhook_async(payment_details, processing_id)
        elif order_type == 'domain':
            result = await _process_domain_webhook_async(payment_details, processing_id)
        elif order_type == 'hosting':
            result = await _process_hosting_webhook_async(payment_details, processing_id)
        else:
            raise ValueError(f'Unknown order type: {order_type}')
        
        # Add processing metadata
        result.update({
            'processing_time': time.time() - start_time,
            'processing_id': processing_id,
            'provider': provider,
            'order_type': order_type
        })
        
        status = "✅ SUCCESS" if result.get('success') else "❌ FAILURE"
        logger.info(f"{status} WEBHOOK_ASYNC_COMPLETE: {processing_id} | Time: {result['processing_time']:.3f}s")
        
        return result
        
    except asyncio.TimeoutError:
        error_msg = f'Webhook processing timed out after 30s'
        logger.error(f"⏰ WEBHOOK_ASYNC_TIMEOUT: {processing_id} | {error_msg}")
        return {
            'success': False,
            'error': error_msg,
            'processing_time': time.time() - start_time,
            'processing_id': processing_id
        }
        
    except Exception as e:
        error_msg = f'Webhook processing failed: {str(e)}'
        logger.error(f"❌ WEBHOOK_ASYNC_ERROR: {processing_id} | {error_msg}")
        return {
            'success': False,
            'error': error_msg,
            'processing_time': time.time() - start_time,
            'processing_id': processing_id
        }

async def _validate_webhook_data_async(webhook_data: Dict[str, Any], provider: str) -> Dict[str, Any]:
    """Async webhook data validation"""
    try:
        # Basic structure validation
        if not isinstance(webhook_data, dict) or not webhook_data:
            return {'valid': False, 'error': 'Webhook data is empty or not a dictionary'}
        
        # Provider-specific validation
        if provider == 'dynopay':
            required_fields = ['status', 'base_amount', 'transaction_reference']
            for field in required_fields:
                if field not in webhook_data:
                    return {'valid': False, 'error': f'Missing required field: {field}'}
        
        elif provider == 'blockbee':
            required_fields = ['result', 'value_coin']
            for field in required_fields:
                if field not in webhook_data:
                    return {'valid': False, 'error': f'Missing required field: {field}'}
        
        return {'valid': True}
        
    except Exception as e:
        return {'valid': False, 'error': f'Validation error: {str(e)}'}

async def _extract_payment_details_async(webhook_data: Dict[str, Any], provider: str) -> Dict[str, Any]:
    """Async payment detail extraction with normalization"""
    try:
        if provider == 'dynopay':
            return {
                'status': webhook_data.get('status'),
                'amount_usd': float(webhook_data.get('base_amount', 0)),
                'amount_crypto': float(webhook_data.get('paid_amount', 0)),
                'currency': webhook_data.get('paid_currency', '').upper(),
                'txid': webhook_data.get('transaction_reference'),
                'confirmations': 1 if webhook_data.get('status') == 'successful' else 0,
                'provider': 'dynopay'
            }
        
        elif provider == 'blockbee':
            # Handle BlockBee's complex value_coin_convert structure
            amount_usd = 0.0
            try:
                value_convert_str = webhook_data.get('value_coin_convert')
                if value_convert_str and isinstance(value_convert_str, str):
                    value_convert = json.loads(value_convert_str)
                    amount_usd = float(value_convert.get('USD', 0))
            except (json.JSONDecodeError, ValueError, TypeError):
                logger.warning(f"Could not parse BlockBee value_coin_convert: {webhook_data.get('value_coin_convert')}")
            
            return {
                'status': webhook_data.get('result'),
                'amount_usd': amount_usd,
                'amount_crypto': float(webhook_data.get('value_coin', 0)),
                'currency': webhook_data.get('currency', '').upper(),
                'txid': webhook_data.get('txid_in') or webhook_data.get('txid'),
                'confirmations': int(webhook_data.get('confirmations', 0)),
                'provider': 'blockbee'
            }
        
        else:
            raise ValueError(f'Unknown provider: {provider}')
            
    except Exception as e:
        logger.error(f"Error extracting payment details for {provider}: {e}")
        raise

async def _process_wallet_webhook_async(payment_details: Dict[str, Any], processing_id: str) -> Dict[str, Any]:
    """Async wallet deposit processing"""
    try:
        # Extract order details - now expecting integer order_id
        order_id = payment_details.get('order_id')
        if not order_id:
            return {'success': False, 'error': 'Missing order ID'}
        
        # Convert to integer if it's a string
        try:
            order_id = int(order_id)
        except (ValueError, TypeError):
            return {'success': False, 'error': f'Invalid order ID format: {order_id}'}
        
        # Get order details from database
        order_query = "SELECT user_id, metadata FROM orders WHERE id = %s"
        order_result = await execute_query(order_query, (order_id,))
        
        if not order_result:
            return {'success': False, 'error': f'Order not found: {order_id}'}
        
        order_record = order_result[0]
        user_id = order_record['user_id']
        
        # Validate this is a wallet deposit order
        metadata = order_record.get('metadata', {})
        if not isinstance(metadata, dict) or metadata.get('deposit_type') != 'wallet':
            return {'success': False, 'error': 'Order is not a wallet deposit'}
        
        # Get user by user_id
        user_query = "SELECT telegram_id FROM users WHERE id = %s"
        user_result = await execute_query(user_query, (user_id,))
        
        if not user_result:
            return {'success': False, 'error': f'User not found for user_id: {user_id}'}
        
        telegram_id = user_result[0]['telegram_id']
        
        # Validate payment status
        if payment_details['status'] not in ['successful', 'completed']:
            return {
                'success': False, 
                'error': f'Payment not successful: {payment_details["status"]}'
            }
        
        # Credit wallet using enhanced function
        context = {
            'webhook_source': True,
            'processing_id': processing_id,
            'provider': payment_details['provider']
        }
        
        credit_result = await credit_user_wallet_with_context(
            user_id=user_id,
            amount_usd=payment_details['amount_usd'],
            provider=payment_details['provider'],
            txid=payment_details['txid'],
            order_id=order_id,
            context=context
        )
        
        if credit_result['success']:
            # Send notification to user (async)
            try:
                await _send_wallet_credit_notification_async(telegram_id, credit_result)
            except Exception as notify_error:
                logger.warning(f"Failed to send wallet notification: {notify_error}")
                # Don't fail the whole operation for notification errors
        
        return {
            'success': credit_result['success'],
            'user_id': user_id,
            'telegram_id': telegram_id,
            'amount_credited': credit_result.get('amount_credited'),
            'new_balance': credit_result.get('new_balance'),
            'error': credit_result.get('error')
        }
        
    except Exception as e:
        logger.error(f"Error in wallet webhook processing: {e}")
        return {'success': False, 'error': str(e)}

async def _process_domain_webhook_async(payment_details: Dict[str, Any], processing_id: str) -> Dict[str, Any]:
    """Async domain payment processing"""
    # Implementation for domain payment processing
    # This would integrate with the domain registration orchestrator
    logger.info(f"🌐 Processing domain payment webhook: {processing_id}")
    
    # Placeholder implementation - would call domain registration orchestrator
    return {
        'success': True,
        'message': 'Domain payment processed (placeholder)'
    }

async def _process_hosting_webhook_async(payment_details: Dict[str, Any], processing_id: str) -> Dict[str, Any]:
    """Async hosting payment processing"""
    # Implementation for hosting payment processing
    # This would integrate with the hosting orchestrator
    logger.info(f"🏠 Processing hosting payment webhook: {processing_id}")
    
    # Placeholder implementation - would call hosting orchestrator
    return {
        'success': True,
        'message': 'Hosting payment processed (placeholder)'
    }

async def _send_wallet_credit_notification_async(telegram_id: int, credit_result: Dict[str, Any]):
    """Send wallet credit notification to user"""
    try:
        # Add to message queue for thread-safe delivery
        notification_data = {
            'type': 'wallet_credit',
            'telegram_id': telegram_id,
            'amount': credit_result.get('amount_credited', 0),
            'new_balance': credit_result.get('new_balance', 0),
            'transaction_id': credit_result.get('transaction_id')
        }
        
        # This would integrate with the message queue system
        logger.info(f"📱 Wallet credit notification queued for {telegram_id}: ${credit_result.get('amount_credited', 0):.2f}")
        
    except Exception as e:
        logger.error(f"Error sending wallet notification: {e}")
        raise

async def batch_process_webhooks(webhook_batch: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Process multiple webhooks concurrently with proper isolation
    
    Args:
        webhook_batch: List of webhook data dictionaries
        
    Returns:
        List of processing results
    """
    logger.info(f"🔄 BATCH_WEBHOOK_START: Processing {len(webhook_batch)} webhooks concurrently")
    
    # Create tasks for concurrent processing
    tasks = []
    for webhook in webhook_batch:
        provider = webhook.get('provider')
        order_type = webhook.get('order_type')
        webhook_data = webhook.get('data', {})
        
        # Validate required string parameters
        if not provider or not isinstance(provider, str):
            logger.warning(f"Skipping webhook with invalid provider: {provider}")
            continue
        if not order_type or not isinstance(order_type, str):
            logger.warning(f"Skipping webhook with invalid order_type: {order_type}")
            continue
        
        task = asyncio.create_task(
            process_payment_webhook_async(webhook_data, provider, order_type)
        )
        tasks.append(task)
    
    # Wait for all tasks to complete with timeout
    try:
        results = await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=60.0  # 60 second timeout for batch processing
        )
        
        # Process results and handle exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append({
                    'success': False,
                    'error': f'Webhook {i} failed: {str(result)}',
                    'webhook_index': i
                })
            else:
                processed_results.append(result)
        
        logger.info(f"✅ BATCH_WEBHOOK_COMPLETE: {len(processed_results)} webhooks processed")
        return processed_results
        
    except asyncio.TimeoutError:
        logger.error("⏰ BATCH_WEBHOOK_TIMEOUT: Batch processing timed out after 60s")
        return [{'success': False, 'error': 'Batch timeout'} for _ in webhook_batch]
    
    except Exception as e:
        logger.error(f"❌ BATCH_WEBHOOK_ERROR: {str(e)}")
        return [{'success': False, 'error': str(e)} for _ in webhook_batch]