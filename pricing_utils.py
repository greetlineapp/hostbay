"""
Pricing utilities for domain registration and hosting services
Currency formatting and price calculation functions
"""

import logging
from typing import Union, Optional
from decimal import Decimal, ROUND_HALF_UP

logger = logging.getLogger(__name__)

def format_money(amount: Union[float, int, Decimal], currency: str = "USD", show_currency: bool = True) -> str:
    """
    Format monetary amount for display
    
    Args:
        amount: Amount to format
        currency: Currency code (default: USD)
        show_currency: Whether to show currency symbol
        
    Returns:
        str: Formatted money string
    """
    try:
        # Convert to Decimal for precise arithmetic
        if isinstance(amount, (int, float)):
            decimal_amount = Decimal(str(amount))
        else:
            decimal_amount = amount
            
        # Round to 2 decimal places
        rounded_amount = decimal_amount.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        
        # Format the number
        formatted = f"{rounded_amount:.2f}"
        
        if show_currency:
            currency_symbols = {
                'USD': '$',
                'EUR': '€',
                'GBP': '£',
                'BTC': '₿',
                'ETH': 'Ξ'
            }
            
            symbol = currency_symbols.get(currency.upper(), currency.upper())
            if currency.upper() in ['BTC', 'ETH']:
                return f"{formatted} {symbol}"
            else:
                return f"{symbol}{formatted}"
        
        return formatted
        
    except Exception as e:
        logger.warning(f"Error formatting money: {e}")
        return str(amount)

def calculate_marked_up_price(base_price: Union[float, Decimal], markup_percentage: float = 15.0) -> Decimal:
    """
    Calculate marked up price for reseller margin
    
    Args:
        base_price: Base price from provider
        markup_percentage: Markup percentage (default: 15%)
        
    Returns:
        Decimal: Marked up price
    """
    try:
        if isinstance(base_price, (int, float)):
            base_decimal = Decimal(str(base_price))
        else:
            base_decimal = base_price
            
        # Ensure markup_percentage is numeric to prevent string/int division errors
        if isinstance(markup_percentage, str):
            markup_percentage = float(markup_percentage)
        elif markup_percentage is None:
            markup_percentage = 15.0
            
        markup_multiplier = Decimal(str(1 + (markup_percentage / 100)))
        marked_up = base_decimal * markup_multiplier
        
        # Round to 2 decimal places
        return marked_up.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        
    except Exception as e:
        logger.warning(f"Error calculating markup: {e}")
        return Decimal(str(base_price))

def calculate_discount_price(original_price: Union[float, Decimal], discount_percentage: float) -> Decimal:
    """
    Calculate discounted price
    
    Args:
        original_price: Original price
        discount_percentage: Discount percentage
        
    Returns:
        Decimal: Discounted price
    """
    try:
        if isinstance(original_price, (int, float)):
            price_decimal = Decimal(str(original_price))
        else:
            price_decimal = original_price
            
        discount_multiplier = Decimal(str(1 - (discount_percentage / 100)))
        discounted = price_decimal * discount_multiplier
        
        # Ensure minimum price
        min_price = Decimal('0.01')
        if discounted < min_price:
            discounted = min_price
            
        return discounted.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        
    except Exception as e:
        logger.warning(f"Error calculating discount: {e}")
        return Decimal(str(original_price))

def convert_currency(amount: Union[float, Decimal], from_currency: str, to_currency: str, 
                    exchange_rate: Optional[float] = None) -> Decimal:
    """
    Convert amount between currencies
    
    Args:
        amount: Amount to convert
        from_currency: Source currency
        to_currency: Target currency
        exchange_rate: Exchange rate (if None, returns original amount)
        
    Returns:
        Decimal: Converted amount
    """
    try:
        if from_currency.upper() == to_currency.upper():
            return Decimal(str(amount))
            
        if exchange_rate is None:
            logger.warning(f"No exchange rate provided for {from_currency} -> {to_currency}")
            return Decimal(str(amount))
            
        if isinstance(amount, (int, float)):
            amount_decimal = Decimal(str(amount))
        else:
            amount_decimal = amount
            
        rate_decimal = Decimal(str(exchange_rate))
        converted = amount_decimal * rate_decimal
        
        return converted.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        
    except Exception as e:
        logger.warning(f"Error converting currency: {e}")
        return Decimal(str(amount))

class PricingConfig:
    """Configuration class for pricing settings"""
    
    def __init__(self):
        self.default_markup = 15.0  # 15% markup
        self.default_currency = "USD"
        self.minimum_price = Decimal('0.01')
        
    def get_markup_percentage(self, service_type: str = "default") -> float:
        """Get markup percentage for service type"""
        markup_map = {
            'domain': 15.0,
            'hosting': 20.0,
            'ssl': 25.0,
            'default': 15.0
        }
        return markup_map.get(service_type, self.default_markup)

def format_price_display(price: Union[float, Decimal], currency: str = "USD") -> str:
    """
    Format price for display in UI elements
    
    Args:
        price: Price to format
        currency: Currency code
        
    Returns:
        str: Formatted price string for display
    """
    return format_money(price, currency, show_currency=True)

logger.info("🔧 Pricing utilities system initialized")