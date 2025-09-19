"""
BlockBee service implementation for cryptocurrency payment processing
"""

import logging
import os
import httpx
from typing import Dict, Optional
from admin_alerts import send_critical_alert, send_error_alert, send_warning_alert

logger = logging.getLogger(__name__)

class BlockBeeService:
    """BlockBee cryptocurrency payment service"""
    
    def __init__(self):
        self.api_key = os.getenv('BLOCKBEE_API_KEY')
        self.base_url = "https://api.blockbee.io"
        if self.api_key:
            logger.info("🔧 BlockBee service initialized with API key")
        else:
            logger.info("🔧 BlockBee service initialized (no API key configured)")
    
    def is_available(self) -> bool:
        """Check if BlockBee service is available"""
        return bool(self.api_key)
    
    async def create_payment_address(self, currency: str, order_id: str, value: float, user_id: int, idempotency_key: Optional[str] = None) -> Optional[Dict]:
        """Create payment address via BlockBee API"""
        if not self.api_key:
            logger.warning("⚠️ BlockBee create_payment_address called but service not configured")
            return None
        
        try:
            # BlockBee API format: GET /{ticker}/create/?callback={webhook_url}&apikey={api_key}
            from utils.environment import get_webhook_url
            webhook_url = get_webhook_url('blockbee')
            
            async with httpx.AsyncClient() as client:
                params = {
                    'apikey': self.api_key,
                    'callback': f"{webhook_url}?order_id={order_id}&user_id={user_id}",
                    'pending': '1',  # Receive webhooks for unconfirmed transactions
                    'convert': '1'   # Auto-convert to preferred currency
                }
                
                response = await client.get(
                    f"{self.base_url}/{currency.lower()}/create/",
                    params=params,
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('status') == 'success':
                        address_in = result.get('address_in')
                        logger.info(f"✅ BlockBee created payment address for {currency.upper()}: {address_in}")
                        return {
                            'address': address_in,
                            'callback_url': result.get('callback_url'),
                            'minimum_transaction': result.get('minimum_transaction_coin'),
                            'priority': result.get('priority', 'default')
                        }
                    else:
                        error_msg = result.get('error', 'Unknown error')
                        logger.error(f"❌ BlockBee API error: {error_msg}")
                        # Send admin alert for BlockBee API error
                        await send_error_alert(
                            "BlockBee",
                            f"Payment address creation failed: {error_msg}",
                            "payment_processing",
                            {
                                "currency": currency,
                                "order_id": order_id,
                                "user_id": user_id,
                                "api_error": error_msg,
                                "api_response": result
                            }
                        )
                        return None
                else:
                    logger.error(f"❌ BlockBee API error: {response.status_code} - {response.text}")
                    # Send admin alert for BlockBee HTTP error
                    await send_critical_alert(
                        "BlockBee",
                        f"Payment address creation API failure: HTTP {response.status_code}",
                        "external_api",
                        {
                            "currency": currency,
                            "order_id": order_id,
                            "user_id": user_id,
                            "http_status": response.status_code,
                            "api_response": response.text
                        }
                    )
                    return None
                    
        except Exception as e:
            logger.error(f"❌ BlockBee payment address creation failed: {str(e)}")
            # Send admin alert for BlockBee exception
            await send_critical_alert(
                "BlockBee",
                f"Payment address creation exception: {str(e)}",
                "payment_processing",
                {
                    "currency": currency,
                    "order_id": order_id,
                    "user_id": user_id,
                    "exception": str(e)
                }
            )
            return None
    
    async def process_refund(
        self, 
        currency: str,
        payment_address: str, 
        amount: float, 
        reason: str = "Hosting bundle failure"
    ) -> Optional[Dict]:
        """Process refund via BlockBee API (Note: BlockBee may not support automated refunds)"""
        if not self.is_available():
            logger.warning("⚠️ BlockBee process_refund called but service not configured")
            return None
        
        try:
            # Note: BlockBee may not have an automated refund API
            # This implementation logs the refund request and returns pending status
            # for manual processing by the support team
            
            logger.info(f"📝 BlockBee refund request logged: {payment_address} - ${amount}")
            logger.info(f"📝 Refund reason: {reason}")
            
            # In a production implementation, you might:
            # 1. Log to a refund queue for manual processing
            # 2. Send notification to support team
            # 3. Create a support ticket automatically
            
            return {
                'status': 'pending',
                'refund_method': 'manual_processing',
                'amount': amount,
                'currency': currency.upper(),
                'payment_address': payment_address,
                'provider_response': 'Refund request logged for manual processing by support team'
            }
                    
        except Exception as e:
            logger.error(f"❌ BlockBee refund processing failed: {str(e)}")
            # Send admin alert for BlockBee refund exception
            await send_error_alert(
                "BlockBee",
                f"Refund processing exception: {str(e)}",
                "payment_processing",
                {
                    "currency": currency,
                    "payment_address": payment_address,
                    "amount": amount,
                    "reason": reason,
                    "exception": str(e)
                }
            )
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    async def check_payment_status(self, currency: str, payment_address: str) -> Optional[Dict]:
        """Check payment status via BlockBee API"""
        if not self.api_key:
            logger.warning("⚠️ BlockBee check_payment_status called but service not configured")
            return None
            
        try:
            async with httpx.AsyncClient() as client:
                params = {
                    'apikey': self.api_key
                }
                
                response = await client.get(
                    f"{self.base_url}/{currency.lower()}/info/{payment_address}/",
                    params=params,
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('status') == 'success':
                        return result
                    else:
                        logger.error(f"❌ BlockBee status error: {result.get('error', 'Unknown error')}")
                        return None
                else:
                    logger.error(f"❌ BlockBee status check error: {response.status_code} - {response.text}")
                    return None
                    
        except Exception as e:
            logger.error(f"❌ BlockBee status check failed: {str(e)}")
            return None