"""
Unified Cryptocurrency Configuration for HostBay Bot
Ensures consistent crypto options across wallet funding, hosting purchases, and domain registration
"""

import logging
from typing import List, Dict, Tuple
from services.payment_provider import get_current_provider_name

logger = logging.getLogger(__name__)

class CryptoConfig:
    """Unified cryptocurrency configuration manager"""
    
    # Intersection of supported currencies between DynoPay and BlockBee
    SUPPORTED_CURRENCIES = [
        {
            'code': 'btc',
            'name': 'Bitcoin',
            'symbol': 'BTC',
            'icon': '₿'
        },
        {
            'code': 'eth', 
            'name': 'Ethereum',
            'symbol': 'ETH',
            'icon': 'Ξ'
        },
        {
            'code': 'ltc',
            'name': 'Litecoin', 
            'symbol': 'LTC',
            'icon': 'Ł'
        },
        {
            'code': 'doge',
            'name': 'Dogecoin',
            'symbol': 'DOGE',
            'icon': '🐕'
        },
        {
            'code': 'usdt_trc20',
            'name': 'USDT (TRC20)',
            'symbol': 'USDT',
            'icon': '₮'
        },
        {
            'code': 'usdt_erc20',
            'name': 'USDT (ERC20)', 
            'symbol': 'USDT',
            'icon': '₮'
        }
    ]
    
    @classmethod
    def get_supported_currencies(cls) -> List[Dict]:
        """Get list of supported cryptocurrencies"""
        return cls.SUPPORTED_CURRENCIES.copy()
    
    @classmethod 
    def get_currency_by_code(cls, code: str) -> Dict:
        """Get currency info by code"""
        code = code.lower()
        for currency in cls.SUPPORTED_CURRENCIES:
            if currency['code'] == code:
                return currency.copy()
        return {}
    
    @classmethod
    def get_display_name(cls, code: str) -> str:
        """Get display name for currency"""
        currency = cls.get_currency_by_code(code)
        return currency.get('name', code.upper())
    
    @classmethod
    def get_symbol(cls, code: str) -> str:
        """Get symbol for currency"""
        currency = cls.get_currency_by_code(code)
        return currency.get('symbol', code.upper())
    
    @classmethod
    def get_icon(cls, code: str) -> str:
        """Get icon for currency"""
        currency = cls.get_currency_by_code(code)
        return currency.get('icon', '💰')
    
    @classmethod
    def is_supported(cls, code: str) -> bool:
        """Check if currency is supported"""
        code = code.lower()
        return any(c['code'] == code for c in cls.SUPPORTED_CURRENCIES)
    
    @classmethod
    def get_payment_button_data(cls) -> List[Tuple[str, str, str]]:
        """Get payment button data: (display_text, callback_data_suffix, icon)"""
        buttons = []
        for currency in cls.SUPPORTED_CURRENCIES:
            display = f"{currency['icon']} {currency['name']}"
            callback_suffix = currency['code']
            icon = currency['icon']
            buttons.append((display, callback_suffix, icon))
        return buttons

# Create global instance
crypto_config = CryptoConfig()