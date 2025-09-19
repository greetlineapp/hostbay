"""
Brand configuration utility for white-label customization
Handles configurable branding and removes hardcoded brand references
Enhanced with multi-language support for internationalization
"""

import os
import logging
from typing import Dict, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from localization import LanguageConfig

# Import localization system for multi-language support
try:
    from localization import t, get_language_config, detect_user_language
    LOCALIZATION_AVAILABLE = True
except ImportError:
    # Fallback if localization system is not available
    LOCALIZATION_AVAILABLE = False
    def t(key: str, lang_code: str = 'en', **kwargs) -> str:
        """Fallback translation function"""
        return key
    
    def get_language_config() -> Any:
        """Fallback function when localization is not available"""
        class FallbackLanguageConfig:
            def _get_nested_translation(self, key: str, lang_code: str) -> Optional[str]:
                return None
        return FallbackLanguageConfig()
    
    def detect_user_language(telegram_lang_code: Optional[str]) -> str:
        """Fallback function when localization is not available"""
        return 'en'

logger = logging.getLogger(__name__)

class BrandConfig:
    """Configuration class for white-label branding settings"""
    
    _instance = None
    _initialized = False
    
    def __new__(cls):
        """Singleton pattern to ensure consistent configuration"""
        if cls._instance is None:
            cls._instance = super(BrandConfig, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        # Only initialize once to prevent inconsistent environment variable loading
        if BrandConfig._initialized:
            return
            
        # Use fallback defaults for empty or missing environment variables with XML error protection
        raw_platform_name = os.getenv('PLATFORM_NAME') or 'HostBay'
        raw_platform_tagline = os.getenv('PLATFORM_TAGLINE') or 'Domain & Hosting Services'
        raw_support_contact = os.getenv('SUPPORT_CONTACT') or '@Hostbay_support'
        raw_hostbay_channel = os.getenv('HOSTBAY_CHANNEL') or '@Hostbay'
        raw_hostbay_email = os.getenv('HOSTBAY_EMAIL') or 'hello@hostbay.io'
        
        # Sanitize platform name to prevent XML error contamination
        self.platform_name = self._sanitize_config_value(raw_platform_name, 'HostBay')
        self.platform_tagline = self._sanitize_config_value(raw_platform_tagline, 'Domain & Hosting Services')
        self.support_contact = self._sanitize_config_value(raw_support_contact, '@Hostbay_support')
        self.hostbay_channel = self._sanitize_config_value(raw_hostbay_channel, '@Hostbay')
        self.hostbay_email = self._sanitize_config_value(raw_hostbay_email, 'hello@hostbay.io')
        
        # Generic service references for user-facing messages
        self.domain_registrar_name = os.getenv('DOMAIN_REGISTRAR_DISPLAY', 'domain registrar')
        self.payment_processor_name = os.getenv('PAYMENT_PROCESSOR_DISPLAY', 'payment processor')
        self.dns_service_name = os.getenv('DNS_SERVICE_DISPLAY', 'DNS service')
        
        BrandConfig._initialized = True
        logger.debug(f"🔧 Brand configuration initialized: platform='{self.platform_name}'")
    
    def _sanitize_config_value(self, value: str, fallback: str) -> str:
        """
        Sanitize configuration values to prevent XML error contamination
        
        Args:
            value: Raw configuration value from environment
            fallback: Safe fallback value
            
        Returns:
            Sanitized configuration value
        """
        if not value or not isinstance(value, str):
            return fallback
            
        # Check for XML error responses or other problematic content
        value = value.strip()
        
        # Detect XML error responses
        if (value.startswith('<?xml') or 
            '<Error>' in value or 
            '<Code>' in value or 
            'ExpiredToken' in value or
            len(value) > 100):
            logger.warning(f"🚨 Detected corrupted configuration value (XML/Error response), using fallback: '{fallback}'")
            return fallback
            
        # Ensure reasonable length
        if len(value) > 50:
            logger.warning(f"⚠️ Very long configuration value detected, using fallback: '{fallback}'")
            return fallback
            
        return value
        
    def get_config_info(self) -> Dict[str, Any]:
        """Get current brand configuration for logging/debugging"""
        return {
            'platform_name': self.platform_name,
            'platform_tagline': self.platform_tagline,
            'support_contact': self.support_contact,
            'hostbay_channel': self.hostbay_channel,
            'hostbay_email': self.hostbay_email,
            'domain_registrar_name': self.domain_registrar_name,
            'payment_processor_name': self.payment_processor_name,
            'dns_service_name': self.dns_service_name
        }

def get_platform_name() -> str:
    """Get the configured platform name"""
    config = BrandConfig()
    return config.platform_name

def get_platform_tagline() -> str:
    """Get the configured platform tagline"""
    config = BrandConfig()
    return config.platform_tagline

def get_support_contact() -> str:
    """Get the configured support contact"""
    config = BrandConfig()
    return config.support_contact

def get_hostbay_channel() -> str:
    """Get the configured Hostbay channel"""
    config = BrandConfig()
    return config.hostbay_channel

def get_hostbay_email() -> str:
    """Get the configured Hostbay email"""
    config = BrandConfig()
    return config.hostbay_email

def get_welcome_message(lang_code: str = 'en') -> str:
    """Get branded welcome message for the /start command with multi-language support"""
    config = BrandConfig()
    
    if LOCALIZATION_AVAILABLE:
        from message_utils import t_fmt
        return t_fmt('welcome.greeting', lang_code)
    else:
        # Fallback to original hardcoded message
        return f"""🚀 <b>Welcome to {config.platform_name}!</b>

{config.platform_tagline}

What would you like to do?"""

def get_service_error_message(service_type: str, action: str, lang_code: str = 'en') -> str:
    """
    Get generic error message for service failures
    
    Args:
        service_type: Type of service ('domain', 'dns', 'payment', 'hosting')
        action: Action being performed ('registration', 'management', 'processing', etc.)
        
    Returns:
        Generic error message without revealing service provider names
    """
    config = BrandConfig()
    
    if LOCALIZATION_AVAILABLE:
        # Use translation system with error categories
        error_key_map = {
            'domain': 'errors.domain_registration_failed' if action == 'registration' else 'errors.service_unavailable',
            'dns': 'errors.dns_update_failed' if action == 'update' else 'errors.service_unavailable',
            'payment': 'errors.payment_failed' if action == 'processing' else 'errors.service_unavailable',
            'hosting': 'errors.hosting_setup_failed' if action == 'setup' else 'errors.service_unavailable'
        }
        
        error_key = error_key_map.get(service_type, 'errors.service_unavailable')
        from message_utils import t_fmt
        return t_fmt(error_key, lang_code)
    else:
        # Fallback to original hardcoded messages
        service_messages = {
            'domain': f"Sorry, we're having trouble with domain {action} right now. Please try again in a few moments.",
            'dns': f"DNS {action} is temporarily unavailable. Please try again shortly.",
            'payment': f"Payment {action} is experiencing delays. Please try again or contact {config.support_contact}.",
            'hosting': f"Hosting {action} is temporarily unavailable. Please try again later."
        }
        
        return service_messages.get(service_type, f"Service temporarily unavailable. Please try again or contact {config.support_contact}.")

def get_payment_success_message(amount: str, crypto_currency: str, lang_code: str = 'en') -> str:
    """Get branded payment success message with multi-language support"""
    from message_utils import create_success_message, escape_html
    config = BrandConfig()
    
    if LOCALIZATION_AVAILABLE:
        title = t('success.payment_confirmed', lang_code)
        from message_utils import t_fmt
        details = t_fmt('success.payment_details', lang_code,
                        amount=escape_html(amount),
                        currency=escape_html(crypto_currency))
        return create_success_message(title, details)
    else:
        # Fallback to original hardcoded message
        return create_success_message("Payment Confirmed!", f"Thank you for your payment of {escape_html(amount)} {escape_html(crypto_currency)}.\n\nYour {config.platform_name} wallet has been credited and you can now proceed with your order.\n\n💰 Check your wallet balance with /wallet")

def get_domain_success_message(domain_name: str, lang_code: str = 'en') -> str:
    """Get branded domain registration success message with multi-language support"""
    config = BrandConfig()
    
    if LOCALIZATION_AVAILABLE:
        title = t('success.domain_registered', lang_code)
        details = t('success.domain_details', lang_code, domain=domain_name)
        from message_utils import create_success_message
        return create_success_message(title, details)
    else:
        # Fallback to original hardcoded message
        return f"🎉 <b>Domain Registration Successful!</b>\n\n<b>{domain_name}</b> has been registered successfully!\n\nYou can now:\n• Set up DNS records\n• Configure hosting\n• Manage domain settings\n\nUse /dns to configure your domain's DNS settings."

def get_dns_management_intro(lang_code: str = 'en') -> str:
    """Get branded DNS management introduction with multi-language support"""
    config = BrandConfig()
    
    if LOCALIZATION_AVAILABLE:
        title = t('dns.title', lang_code)
        select_text = t('dns.select_domain', lang_code)
        return f"{title}\n\n{select_text}"
    else:
        # Fallback to original hardcoded message
        return "🌐 <b>DNS</b>\n\nSelect domain:"

def format_branded_message(template: str, lang_code: str = 'en', translation_key: Optional[str] = None, **kwargs) -> str:
    """
    Format a message template with brand configuration and multi-language support
    
    Args:
        template: Message template with placeholders like {platform_name}, {support_contact}
        lang_code: Language code for translations
        translation_key: Optional translation key to use instead of template
        **kwargs: Additional template variables
        
    Returns:
        Formatted message with brand configuration and translations applied
    """
    config = BrandConfig()
    
    # If translation key is provided and localization is available, use it
    if translation_key and LOCALIZATION_AVAILABLE:
        # Use translation system instead of template
        template = t(translation_key, lang_code, **kwargs)
    
    # Default brand variables
    brand_vars = {
        'platform_name': config.platform_name,
        'platform_tagline': config.platform_tagline,
        'support_contact': config.support_contact,
        'hostbay_channel': config.hostbay_channel,
        'hostbay_email': config.hostbay_email,
        'domain_registrar': config.domain_registrar_name,
        'payment_processor': config.payment_processor_name,
        'dns_service': config.dns_service_name
    }
    
    # Merge with additional variables
    brand_vars.update(kwargs)
    
    try:
        return template.format(**brand_vars)
    except KeyError as e:
        logger.warning(f"⚠️ Missing template variable: {e}")
        return template

def validate_brand_config() -> bool:
    """
    Validate that brand configuration is reasonable (non-blocking)
    
    Returns:
        True if configuration is valid, False otherwise
    """
    config = BrandConfig()
    
    # Validate platform name - allow empty with fallback to default
    if not config.platform_name or len(config.platform_name.strip()) == 0:
        logger.warning("⚠️ Platform name is empty - using default fallback")
        config.platform_name = "HostBay"  # Apply default fallback
        
    if len(config.platform_name) > 50:
        logger.warning(f"⚠️ Very long platform name detected: {config.platform_name}")
    
    # Validate platform tagline
    if not config.platform_tagline or len(config.platform_tagline.strip()) == 0:
        logger.warning("⚠️ Platform tagline is empty - using default")
        
    if len(config.platform_tagline) > 100:
        logger.warning(f"⚠️ Very long platform tagline detected: {config.platform_tagline}")
    
    # Validate support contact
    if not config.support_contact or len(config.support_contact.strip()) == 0:
        logger.warning("⚠️ Support contact is empty - using default")
    
    # Log configuration for transparency
    logger.info(f"✅ Brand configuration validated: platform='{config.platform_name}', tagline='{config.platform_tagline}', support='{config.support_contact}'")
    
    return True

def get_startup_message() -> str:
    """Get branded startup message for logging"""
    config = BrandConfig()
    return f"🚀 Starting {config.platform_name} Telegram Bot with Enhanced Payment Integration..."

def get_bot_description() -> str:
    """Get branded bot description"""
    config = BrandConfig()
    return f"{config.platform_name} - {config.platform_tagline}"

# Multi-language utility functions

def get_user_language_from_telegram(telegram_user) -> str:
    """
    Get user language preference from Telegram user object with fallback
    
    Args:
        telegram_user: Telegram User object from update
        
    Returns:
        Detected language code
    """
    if LOCALIZATION_AVAILABLE and hasattr(telegram_user, 'language_code'):
        return detect_user_language(telegram_user.language_code)
    return 'en'

async def get_user_language_preference(user_id: int) -> str:
    """
    Get user language preference with caching and fallback to Telegram detection
    
    Args:
        user_id: Telegram user ID
        
    Returns:
        User's preferred language code
    """
    if LOCALIZATION_AVAILABLE:
        try:
            from localization import get_user_language_preference as get_lang_pref
            return await get_lang_pref(user_id)
        except Exception as e:
            logger.debug(f"Could not get user language preference: {e}")
    return 'en'

def create_localized_message(message_key: str, lang_code: str = 'en', **kwargs) -> str:
    """
    Create a localized message with brand variables automatically included
    
    Args:
        message_key: Translation key
        lang_code: Language code
        **kwargs: Additional variables
        
    Returns:
        Localized message with brand configuration applied
    """
    config = BrandConfig()
    
    # Include brand variables automatically
    brand_vars = {
        'platform_name': config.platform_name,
        'platform_tagline': config.platform_tagline,
        'support_contact': config.support_contact,
        'hostbay_channel': config.hostbay_channel,
        'hostbay_email': config.hostbay_email,
        'domain_registrar': config.domain_registrar_name,
        'payment_processor': config.payment_processor_name,
        'dns_service': config.dns_service_name
    }
    brand_vars.update(kwargs)
    
    if LOCALIZATION_AVAILABLE:
        return t(message_key, lang_code, **brand_vars)
    else:
        # Fallback to key if localization not available
        return message_key

def get_localization_status() -> Dict[str, Any]:
    """
    Get current localization system status for debugging
    
    Returns:
        Status information about localization system
    """
    status = {
        'localization_available': LOCALIZATION_AVAILABLE,
        'supported_languages': [],
        'default_language': 'en'
    }
    
    if LOCALIZATION_AVAILABLE:
        try:
            from localization import get_supported_languages
            status['supported_languages'] = list(get_supported_languages().keys())
        except Exception as e:
            logger.debug(f"Could not get supported languages: {e}")
    
    return status

# Initialize and validate configuration on module import (non-blocking)
# Validation is now non-blocking to prevent startup failures
try:
    validate_brand_config()
    if LOCALIZATION_AVAILABLE:
        logger.info("✅ Brand configuration initialized with multi-language support")
    else:
        logger.info("✅ Brand configuration initialized (localization system not available)")
except Exception as e:
    logger.warning(f"⚠️ Brand configuration validation encountered an issue: {e}")
    logger.info("🔄 Using default brand configuration to continue startup")