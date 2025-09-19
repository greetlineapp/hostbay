"""
DynoPay service implementation for cryptocurrency payment processing
"""

import logging
import os
import httpx
from typing import Dict, Optional
from admin_alerts import send_critical_alert, send_error_alert, send_warning_alert

logger = logging.getLogger(__name__)

class DynoPayService:
    """DynoPay cryptocurrency payment service"""
    
    def __init__(self):
        self.api_key = os.getenv('DYNOPAY_API_KEY')
        self.wallet_token = os.getenv('DYNOPAY_WALLET_TOKEN')
        self.base_url = os.getenv('DYNOPAY_BASE_URL', 'https://user-api.dynopay.com/api')
        
        if self.api_key and self.wallet_token:
            logger.info("🔧 DynoPay service initialized with API key and wallet token")
        else:
            logger.info("🔧 DynoPay service initialized (missing credentials)")
    
    def is_available(self) -> bool:
        """Check if DynoPay service is available"""
        return bool(self.api_key and self.wallet_token)
    
    async def create_payment_address(self, currency: str, order_id: str, value: float, user_id: int, idempotency_key: Optional[str] = None) -> Optional[Dict]:
        """Create payment address via DynoPay API"""
        if not self.is_available():
            logger.warning("⚠️ DynoPay create_payment_address called but service not configured")
            return None
        
        try:
            # Get webhook URL using environment detection
            from utils.environment import get_webhook_url
            webhook_url = get_webhook_url('dynopay')
            
            # Map currency to DynoPay format
            currency_map = {
                'btc': 'BTC',
                'eth': 'ETH', 
                'ltc': 'LTC',
                'doge': 'DOGE',
                'usdt': 'USDT',  # ERC20
                'usdt_erc20': 'USDT-ERC20',  # Fixed: handle underscore format
                'usdt-erc20': 'USDT-ERC20',  # Also handle dash format
                'usdt_trc20': 'USDT-TRC20',  # Fixed: handle underscore format
                'usdt-trc20': 'USDT-TRC20'   # Also handle dash format
            }
            
            dynopay_currency = currency_map.get(currency.lower(), currency.upper())
            
            # DynoPay requires minimum $1 USD - adjust amount if needed
            if value == 0 or value < 1:
                value = 5.0  # Set minimum $5 USD for wallet deposits
                logger.info(f"💰 DynoPay: Adjusted amount to ${value} USD (minimum required)")
            
            amount_to_use = value
            logger.info(f"💰 DynoPay: Using amount ${amount_to_use} USD for {dynopay_currency}")
            
            async with httpx.AsyncClient() as client:
                headers = {
                    "accept": "application/json",
                    "content-type": "application/json",
                    "x-api-key": self.api_key,
                    "Authorization": f"Bearer {self.wallet_token}"
                }
                
                # Generate secure callback token for webhook authentication
                import secrets
                auth_token = secrets.token_urlsafe(32)
                
                data = {
                    "amount": amount_to_use,
                    "currency": dynopay_currency,
                    "redirect_uri": f"{webhook_url}?order_id={order_id}&auth_token={auth_token}",
                    "meta_data": {
                        "product_name": "crypto_payment",
                        "refId": order_id,
                        "user_id": str(user_id),
                        "order_id": order_id,
                        "original_amount": value,  # Store original amount for reference
                        "wallet_deposit": value <= 0  # Flag for wallet deposits
                    }
                }
                
                response = await client.post(
                    f"{self.base_url}/user/cryptoPayment",
                    json=data,
                    headers=headers,
                    timeout=10.0  # PERFORMANCE OPTIMIZATION: Reduced from 15s to 10s
                )
                
                if response.status_code == 200:
                    result = response.json()
                    # DynoPay returns address in nested 'data' object
                    response_data = result.get('data', {})
                    payment_address = response_data.get('address') or result.get('payment_address') or result.get('address')
                    
                    if payment_address:
                        logger.info(f"✅ DynoPay created payment address for {dynopay_currency}: {payment_address}")
                        return {
                            'address': payment_address,
                            'currency': dynopay_currency,
                            'amount': amount_to_use,
                            'amount_display': amount_to_use,
                            'original_amount': value,
                            'is_wallet_deposit': value <= 0,
                            'redirect_uri': data['redirect_uri'],  # Use original request data
                            'auth_token': auth_token,
                            'meta_data': data['meta_data']  # Use original request data
                        }
                    else:
                        logger.error(f"❌ DynoPay API response missing payment address: {result}")
                        # Send admin alert for missing payment address
                        await send_error_alert(
                            "DynoPay",
                            f"Payment address creation failed - missing address in response",
                            "payment_processing",
                            {
                                "currency": dynopay_currency,
                                "amount": amount_to_use,
                                "order_id": order_id,
                                "user_id": user_id,
                                "api_response": result
                            }
                        )
                        return None
                else:
                    logger.error(f"❌ DynoPay API error: {response.status_code} - {response.text}")
                    # Send admin alert for DynoPay API error
                    await send_critical_alert(
                        "DynoPay",
                        f"Payment address creation API failure: HTTP {response.status_code}",
                        "external_api",
                        {
                            "currency": dynopay_currency,
                            "amount": amount_to_use,
                            "order_id": order_id,
                            "user_id": user_id,
                            "http_status": response.status_code,
                            "api_response": response.text
                        }
                    )
                    return None
                    
        except Exception as e:
            logger.error(f"❌ DynoPay payment address creation failed: {str(e)}")
            # Send admin alert for DynoPay exception
            await send_critical_alert(
                "DynoPay",
                f"Payment address creation exception: {str(e)}",
                "payment_processing",
                {
                    "currency": currency,
                    "amount": value,
                    "order_id": order_id,
                    "user_id": user_id,
                    "exception": str(e)
                }
            )
            return None
    
    async def process_refund(
        self, 
        payment_id: str, 
        amount: float, 
        currency: str = "USD",
        reason: str = "Hosting bundle failure"
    ) -> Optional[Dict]:
        """Process refund via DynoPay API"""
        if not self.is_available():
            logger.warning("⚠️ DynoPay process_refund called but service not configured")
            return None
        
        try:
            async with httpx.AsyncClient() as client:
                headers = {
                    "accept": "application/json",
                    "content-type": "application/json",
                    "x-api-key": self.api_key,
                    "Authorization": f"Bearer {self.wallet_token}"
                }
                
                data = {
                    "payment_id": payment_id,
                    "amount": amount,
                    "currency": currency,
                    "reason": reason
                }
                
                response = await client.post(
                    f"{self.base_url}/user/refund",
                    json=data,
                    headers=headers,
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    result = response.json()
                    logger.info(f"✅ DynoPay refund processed: {payment_id}")
                    return {
                        'status': 'success',
                        'refund_id': result.get('refund_id'),
                        'amount': amount,
                        'currency': currency,
                        'provider_response': result
                    }
                else:
                    logger.error(f"❌ DynoPay refund API error: {response.status_code} - {response.text}")
                    # Send admin alert for DynoPay refund failure
                    await send_critical_alert(
                        "DynoPay",
                        f"Refund processing failed: HTTP {response.status_code}",
                        "payment_processing",
                        {
                            "payment_id": payment_id,
                            "amount": amount,
                            "currency": currency,
                            "reason": reason,
                            "http_status": response.status_code,
                            "api_response": response.text
                        }
                    )
                    return {
                        'status': 'failed',
                        'error': f"API error: {response.status_code}",
                        'response_text': response.text
                    }
                    
        except Exception as e:
            logger.error(f"❌ DynoPay refund processing failed: {str(e)}")
            # Send admin alert for DynoPay refund exception
            await send_critical_alert(
                "DynoPay",
                f"Refund processing exception: {str(e)}",
                "payment_processing",
                {
                    "payment_id": payment_id,
                    "amount": amount,
                    "currency": currency,
                    "reason": reason,
                    "exception": str(e)
                }
            )
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    async def check_payment_status(self, currency: str, payment_address: str) -> Optional[Dict]:
        """Check payment status via DynoPay API"""
        if not self.is_available():
            logger.warning("⚠️ DynoPay check_payment_status called but service not configured")
            return None
            
        try:
            async with httpx.AsyncClient() as client:
                headers = {
                    "accept": "application/json",
                    "x-api-key": self.api_key,
                    "Authorization": f"Bearer {self.wallet_token}"
                }
                
                # DynoPay status endpoint (adjust based on actual API)
                response = await client.get(
                    f"{self.base_url}/payment/status/{currency.upper()}/{payment_address}",
                    headers=headers,
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    return response.json()
                else:
                    logger.error(f"❌ DynoPay status check error: {response.status_code} - {response.text}")
                    return None
                    
        except Exception as e:
            logger.error(f"❌ DynoPay status check failed: {str(e)}")
            return None
    
    def get_supported_currencies(self) -> list:
        """Get list of supported cryptocurrencies"""
        return ['BTC', 'ETH', 'LTC', 'DOGE', 'USDT-TRC20', 'USDT']