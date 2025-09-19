"""Environment detection utilities for production vs development"""

import os
import logging

logger = logging.getLogger(__name__)

def get_webhook_domain() -> str:
    """
    Get the appropriate webhook domain based on environment
    
    Returns:
        str: The domain to use for webhooks
    """
    # Check if we're in a production deployment
    # Production indicators on Replit:
    # 1. REPLIT_DEPLOYMENT environment variable exists (set in deployments)
    # 2. Or we can check if the domain contains 'replit.app' pattern
    
    is_production = os.getenv('REPLIT_DEPLOYMENT') is not None
    
    if is_production:
        # Production deployment - use the custom domain
        domain = 'hostbay.replit.app'
        logger.info(f"🌍 Production environment detected - using domain: {domain}")
        return domain
    else:
        # Development environment - use dev domain
        dev_domain = os.getenv('REPLIT_DOMAINS') or os.getenv('REPLIT_DEV_DOMAIN')
        if not dev_domain:
            logger.warning("⚠️ No development domain found, using localhost fallback")
            dev_domain = 'localhost:5000'
        
        logger.info(f"🔧 Development environment detected - using domain: {dev_domain}")
        return dev_domain

def get_webhook_url(endpoint: str) -> str:
    """
    Get the complete webhook URL for a specific endpoint
    
    Args:
        endpoint: The endpoint path (e.g., 'telegram', 'dynopay', 'blockbee')
        
    Returns:
        str: Complete webhook URL
    """
    domain = get_webhook_domain()
    protocol = 'http' if domain.startswith('localhost') else 'https'
    url = f"{protocol}://{domain}/webhook/{endpoint}"
    
    return url

def is_production_environment() -> bool:
    """
    Check if we're running in production
    
    Returns:
        bool: True if in production, False if in development
    """
    return os.getenv('REPLIT_DEPLOYMENT') is not None