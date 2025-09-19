"""
Payment validation utilities for cryptocurrency payments
Simple validation functions for payment amounts and transaction data
"""

import logging
import os
from typing import Dict, Any, Optional
from decimal import Decimal

logger = logging.getLogger(__name__)

def validate_payment_amount(expected: float, received: float, tolerance: float = 0.01) -> bool:
    """
    Validate payment amount with tolerance
    
    Args:
        expected: Expected payment amount
        received: Received payment amount  
        tolerance: Tolerance percentage (default 1%)
        
    Returns:
        bool: True if payment amount is valid
    """
    try:
        if expected <= 0 or received <= 0:
            return False
            
        # Calculate percentage difference
        diff = abs(expected - received) / expected
        return diff <= tolerance
    except (ZeroDivisionError, TypeError):
        return False

def validate_payment_simple(payment_data: Dict[str, Any]) -> bool:
    """
    Simple payment validation
    
    Args:
        payment_data: Payment data dictionary
        
    Returns:
        bool: True if payment is valid
    """
    try:
        required_fields = ['amount', 'currency', 'transaction_id']
        
        # Check required fields
        for field in required_fields:
            if field not in payment_data:
                logger.warning(f"Missing required field: {field}")
                return False
                
        # Basic amount validation
        amount = payment_data.get('amount', 0)
        if not isinstance(amount, (int, float, Decimal)) or amount <= 0:
            logger.warning(f"Invalid amount: {amount}")
            return False
            
        return True
    except Exception as e:
        logger.error(f"Payment validation error: {e}")
        return False

def log_validation_config():
    """Log validation configuration for debugging"""
    logger.info("🔧 Payment validation system initialized")
    logger.info(f"   • Tolerance: 1%")
    logger.info(f"   • Required fields: amount, currency, transaction_id")