"""
Message formatting and escaping utilities for HostBay Telegram Bot

Provides consistent HTML formatting and escaping for all bot messages
to prevent parsing errors and improve robustness.
Enhanced with multi-language support for internationalization.
"""

import re
import html
import logging
from typing import Tuple, Optional, TYPE_CHECKING, Dict, Any

logger = logging.getLogger(__name__)

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

if TYPE_CHECKING:
    from telegram import InlineKeyboardMarkup


def escape_html(text: str) -> str:
    """
    Escape HTML special characters for safe display in Telegram HTML mode.
    
    Args:
        text: Raw text to escape
        
    Returns:
        HTML-escaped text safe for Telegram
    """
    if not text:
        return ""
    
    # Basic HTML escaping
    escaped = html.escape(str(text))
    
    return escaped


def escape_username(username: str) -> str:
    """
    Safely format Telegram usernames to prevent parsing errors.
    
    Args:
        username: Username like "@HostBay_support" or "HostBay_support"
        
    Returns:
        Safely formatted username
    """
    if not username:
        return ""
    
    # Ensure username starts with @
    if not username.startswith('@'):
        username = f"@{username}"
    
    # Escape for HTML
    return escape_html(username)


def format_code_block(text: str, language: Optional[str] = None) -> str:
    """
    Format text as a code block in HTML.
    
    Args:
        text: Text to format as code
        language: Optional language for syntax highlighting (not used in Telegram)
        
    Returns:
        HTML-formatted code block
    """
    if not text:
        return "<code></code>"
    
    escaped_text = escape_html(text)
    return f"<pre><code>{escaped_text}</code></pre>"


def format_inline_code(text: str) -> str:
    """
    Format text as inline code in HTML.
    
    Args:
        text: Text to format as inline code
        
    Returns:
        HTML-formatted inline code
    """
    if not text:
        return "<code></code>"
    
    escaped_text = escape_html(text)
    return f"<code>{escaped_text}</code>"


def format_bold(text: str) -> str:
    """
    Format text as bold in HTML.
    
    Args:
        text: Text to make bold
        
    Returns:
        HTML-formatted bold text
    """
    if not text:
        return ""
    
    escaped_text = escape_html(text)
    return f"<b>{escaped_text}</b>"


def format_italic(text: str) -> str:
    """
    Format text as italic in HTML.
    
    Args:
        text: Text to make italic
        
    Returns:
        HTML-formatted italic text
    """
    if not text:
        return ""
    
    escaped_text = escape_html(text)
    return f"<i>{escaped_text}</i>"


def format_underline(text: str) -> str:
    """
    Format text as underlined in HTML.
    
    Args:
        text: Text to underline
        
    Returns:
        HTML-formatted underlined text
    """
    if not text:
        return ""
    
    escaped_text = escape_html(text)
    return f"<u>{escaped_text}</u>"


def format_link(text: str, url: str) -> str:
    """
    Format a clickable link in HTML.
    
    Args:
        text: Link text to display
        url: URL to link to
        
    Returns:
        HTML-formatted link
    """
    if not text or not url:
        return escape_html(text) if text else ""
    
    escaped_text = escape_html(text)
    escaped_url = escape_html(url)
    return f'<a href="{escaped_url}">{escaped_text}</a>'


def format_user_mention(user_id: int, name: str) -> str:
    """
    Format a user mention link in HTML.
    
    Args:
        user_id: Telegram user ID
        name: Display name for the user
        
    Returns:
        HTML-formatted user mention
    """
    if not user_id or not name:
        return escape_html(name) if name else ""
    
    escaped_name = escape_html(name)
    return f'<a href="tg://user?id={user_id}">{escaped_name}</a>'


def truncate_with_ellipsis(text: str, max_length: int = 50) -> str:
    """
    Truncate text with ellipsis if it exceeds max_length.
    
    Args:
        text: Text to potentially truncate
        max_length: Maximum length before truncation
        
    Returns:
        Truncated text with ellipsis if needed
    """
    if not text:
        return ""
    
    if len(text) <= max_length:
        return text
    
    return f"{text[:max_length-3]}..."


def escape_content_for_display(content: str, mode: str = "full") -> Tuple[str, str]:
    """
    Enhanced content escaping for different display contexts.
    
    Args:
        content: Raw content to escape
        mode: "full" for complete display, "summary" for truncated display
        
    Returns:
        Tuple of (escaped_content, parse_mode)
    """
    if not content:
        return "(empty)", "HTML"
    
    if mode == "summary":
        # Truncate and escape for summary display
        truncated = truncate_with_ellipsis(content, 80)
        escaped = escape_html(truncated)
        return escaped, "HTML"
    else:
        # Full content display in code block
        return format_code_block(content), "HTML"


def create_success_message(title: str, details: Optional[str] = None) -> str:
    """
    Create a standardized success message.
    
    Args:
        title: Success message title
        details: Optional additional details
        
    Returns:
        Formatted success message
    """
    message = f"✅ {format_bold(title)}"
    if details:
        message += f"\n\n{escape_html(details)}"
    return message


def create_success_message_localized(title_key: str, lang_code: str = 'en', details_key: Optional[str] = None, **kwargs) -> str:
    """
    Create a localized standardized success message.
    
    Args:
        title_key: Translation key for success message title
        lang_code: Language code for translations
        details_key: Optional translation key for additional details
        **kwargs: Variables for translation formatting
        
    Returns:
        Formatted localized success message
    """
    if LOCALIZATION_AVAILABLE:
        title = t(title_key, lang_code, **kwargs)
        message = f"✅ {format_bold(title)}"
        if details_key:
            details = t(details_key, lang_code, **kwargs)
            message += f"\n\n{escape_html(details)}"
        return message
    else:
        # Fallback to keys
        message = f"✅ {format_bold(title_key)}"
        if details_key:
            message += f"\n\n{escape_html(details_key)}"
        return message


def create_error_message(title: str, details: Optional[str] = None) -> str:
    """
    Create a standardized error message.
    
    Args:
        title: Error message title
        details: Optional error details
        
    Returns:
        Formatted error message
    """
    message = f"❌ {format_bold(title)}"
    if details:
        message += f"\n\n{escape_html(details)}"
    return message


def create_error_message_localized(title_key: str, lang_code: str = 'en', details_key: Optional[str] = None, **kwargs) -> str:
    """
    Create a localized standardized error message.
    
    Args:
        title_key: Translation key for error message title
        lang_code: Language code for translations
        details_key: Optional translation key for error details
        **kwargs: Variables for translation formatting
        
    Returns:
        Formatted localized error message
    """
    if LOCALIZATION_AVAILABLE:
        title = t(title_key, lang_code, **kwargs)
        message = f"❌ {format_bold(title)}"
        if details_key:
            details = t(details_key, lang_code, **kwargs)
            message += f"\n\n{escape_html(details)}"
        return message
    else:
        # Fallback to keys
        message = f"❌ {format_bold(title_key)}"
        if details_key:
            message += f"\n\n{escape_html(details_key)}"
        return message


def create_info_message(title: str, details: Optional[str] = None) -> str:
    """
    Create a standardized info message.
    
    Args:
        title: Info message title
        details: Optional additional details
        
    Returns:
        Formatted info message
    """
    message = f"ℹ️ {format_bold(title)}"
    if details:
        message += f"\n\n{escape_html(details)}"
    return message


def create_info_message_localized(title_key: str, lang_code: str = 'en', details_key: Optional[str] = None, **kwargs) -> str:
    """
    Create a localized standardized info message.
    
    Args:
        title_key: Translation key for info message title
        lang_code: Language code for translations
        details_key: Optional translation key for additional details
        **kwargs: Variables for translation formatting
        
    Returns:
        Formatted localized info message
    """
    if LOCALIZATION_AVAILABLE:
        title = t(title_key, lang_code, **kwargs)
        message = f"ℹ️ {format_bold(title)}"
        if details_key:
            details = t(details_key, lang_code, **kwargs)
            message += f"\n\n{escape_html(details)}"
        return message
    else:
        # Fallback to keys
        message = f"ℹ️ {format_bold(title_key)}"
        if details_key:
            message += f"\n\n{escape_html(details_key)}"
        return message


def create_warning_message(title: str, details: Optional[str] = None) -> str:
    """
    Create a standardized warning message.
    
    Args:
        title: Warning message title
        details: Optional warning details
        
    Returns:
        Formatted warning message
    """
    message = f"⚠️ {format_bold(title)}"
    if details:
        message += f"\n\n{escape_html(details)}"
    return message


def create_warning_message_localized(title_key: str, lang_code: str = 'en', details_key: Optional[str] = None, **kwargs) -> str:
    """
    Create a localized standardized warning message.
    
    Args:
        title_key: Translation key for warning message title
        lang_code: Language code for translations
        details_key: Optional translation key for warning details
        **kwargs: Variables for translation formatting
        
    Returns:
        Formatted localized warning message
    """
    if LOCALIZATION_AVAILABLE:
        title = t(title_key, lang_code, **kwargs)
        message = f"⚠️ {format_bold(title)}"
        if details_key:
            details = t(details_key, lang_code, **kwargs)
            message += f"\n\n{escape_html(details)}"
        return message
    else:
        # Fallback to keys
        message = f"⚠️ {format_bold(title_key)}"
        if details_key:
            message += f"\n\n{escape_html(details_key)}"
        return message


# Multi-language utility functions

def translate_message(key: str, lang_code: str = 'en', **kwargs) -> str:
    """
    Convenience function to translate a message with variables
    
    Args:
        key: Translation key
        lang_code: Language code
        **kwargs: Variables for translation formatting
        
    Returns:
        Translated message
    """
    if LOCALIZATION_AVAILABLE:
        return t(key, lang_code, **kwargs)
    else:
        return key

def translate_message_with_brand(key: str, lang_code: str = 'en', **kwargs) -> str:
    """
    Translate a message with automatic brand variables inclusion
    
    Args:
        key: Translation key
        lang_code: Language code
        **kwargs: Additional variables for translation formatting
        
    Returns:
        Translated message with brand variables
    """
    try:
        from brand_config import BrandConfig
        config = BrandConfig()
        
        # Include brand variables automatically
        brand_vars = {
            'platform_name': config.platform_name,
            'platform_tagline': config.platform_tagline,
            'support_contact': config.support_contact,
            'hostbay_email': config.hostbay_email,
            'hostbay_channel': config.hostbay_channel
        }
        brand_vars.update(kwargs)
        
        return translate_message(key, lang_code, **brand_vars)
    except ImportError:
        return translate_message(key, lang_code, **kwargs)

def t_fmt(key: str, lang_code: str = 'en', **kwargs) -> str:
    """
    Enhanced translation wrapper with comprehensive BrandConfig auto-merging and placeholder detection
    
    This function provides:
    - Automatic BrandConfig variables merging
    - Unresolved placeholder detection with error logging
    - Consistent variable substitution across all messages
    
    Args:
        key: Translation key (e.g., 'welcome.greeting')
        lang_code: Language code ('en', 'fr', 'es')
        **kwargs: Additional variables for translation formatting
        
    Returns:
        Translated message with all variables resolved
    """
    try:
        from brand_config import BrandConfig
        config = BrandConfig()
        
        # Auto-merge ALL BrandConfig variables
        brand_vars = {
            'platform_name': config.platform_name,
            'platform_tagline': config.platform_tagline,
            'support_contact': config.support_contact,
            'hostbay_email': config.hostbay_email,
            'hostbay_channel': config.hostbay_channel,
            'domain_registrar_name': getattr(config, 'domain_registrar_name', 'domain registrar'),
            'payment_processor_name': getattr(config, 'payment_processor_name', 'payment processor'),
            'dns_service_name': getattr(config, 'dns_service_name', 'DNS service')
        }
        brand_vars.update(kwargs)
        
        # Get translated message
        message = translate_message(key, lang_code, **brand_vars)
        
        # Detect unresolved placeholders with regex
        import re
        unresolved_placeholders = re.findall(r'\{([^}]+)\}', message)
        if unresolved_placeholders:
            logger.warning(f"🚨 UNRESOLVED PLACEHOLDERS in '{key}' ({lang_code}): {unresolved_placeholders}")
            logger.warning(f"   Message: {message[:100]}...")
            logger.warning(f"   Available vars: {list(brand_vars.keys())}")
        
        return message
        
    except ImportError:
        return translate_message(key, lang_code, **kwargs)
    except Exception as e:
        logger.error(f"❌ Translation error for '{key}' ({lang_code}): {e}")
        return f"[Translation Error: {key}]"

def create_localized_message_with_icon(icon: str, message_key: str, lang_code: str = 'en', **kwargs) -> str:
    """
    Create a localized message with icon prefix
    
    Args:
        icon: Emoji icon to prefix the message
        message_key: Translation key for the message
        lang_code: Language code
        **kwargs: Variables for translation formatting
        
    Returns:
        Formatted message with icon and translation
    """
    translated_text = translate_message(message_key, lang_code, **kwargs)
    return f"{icon} {translated_text}"

def format_localized_list(items_key: str, lang_code: str = 'en', separator: str = '\n• ') -> str:
    """
    Format a localized list from translation keys
    
    Args:
        items_key: Translation key that contains list items
        lang_code: Language code
        separator: Separator between list items
        
    Returns:
        Formatted list string
    """
    if LOCALIZATION_AVAILABLE:
        try:
            config = get_language_config()
            if config is not None:
                items = config._get_nested_translation(items_key, lang_code)
                if isinstance(items, list):
                    return separator.join(items)
                elif isinstance(items, str):
                    return items
        except Exception:
            pass
    
    return items_key

# Brand-specific formatting helpers with localization support
def get_support_username() -> str:
    """Get the properly formatted support username."""
    try:
        from brand_config import BrandConfig
        config = BrandConfig()
        return escape_username(config.support_contact)
    except ImportError:
        return escape_username("@Hostbay_support")

def get_platform_name() -> str:
    """Get the properly formatted platform name."""
    try:
        from brand_config import BrandConfig
        config = BrandConfig()
        return escape_html(config.platform_name)
    except ImportError:
        return escape_html("HostBay")

def create_contact_support_message(platform_name: str, user_id: int, lang_code: str = 'en') -> str:
    """
    Create the contact support message with proper HTML formatting and localization.
    Uses the new t_fmt() system for comprehensive BrandConfig variable substitution.
    
    Args:
        platform_name: Name of the platform (for backward compatibility)
        user_id: User's Telegram ID
        lang_code: Language code for translations
        
    Returns:
        Properly formatted localized contact support message with all variables resolved
    """
    if LOCALIZATION_AVAILABLE:
        # Use the new t_fmt() function with user_id formatting
        title = t_fmt('support.title', lang_code)
        channels = t_fmt('support.channels', lang_code)
        help_with = t_fmt('support.help_with', lang_code)
        response_time = t_fmt('support.response_time', lang_code, user_id=format_inline_code(str(user_id)))
        
        message = f"""{title}

{channels}

{help_with}

{response_time}"""
    else:
        # Enhanced fallback with proper BrandConfig integration
        try:
            from brand_config import BrandConfig
            config = BrandConfig()
            
            message = f"""💬 {format_bold("Contact Support")}

🛠️ Technical: {escape_username(config.support_contact)} • 📧 Business: {escape_html(config.hostbay_email)}
📢 Updates: {escape_username(config.hostbay_channel)}

{format_bold("Help:")} payments, domains, DNS, hosting, wallets, technical issues

{format_bold("Response:")} few hours during business hours • {format_bold("ID:")} {format_inline_code(str(user_id))}"""
        except ImportError:
            # Ultimate fallback - use hardcoded defaults since BrandConfig import failed
            message = f"""💬 {format_bold("Contact Support")}

🛠️ Technical: {escape_username("@Hostbay_support")} • 📧 Business: {escape_html("hello@hostbay.io")}
📢 Updates: {escape_username("@Hostbay")}

{format_bold("Help:")} payments, domains, DNS, hosting, wallets, technical issues

{format_bold("Response:")} few hours during business hours • {format_bold("ID:")} {format_inline_code(str(user_id))}"""
    
    return message


def render_crypto_payment(address: str, crypto_name: str, amount: Optional[str] = None, memo: Optional[str] = None, order_id: Optional[str] = None, expires_minutes: int = 15, lang_code: str = 'en') -> Tuple[str, 'InlineKeyboardMarkup']:
    """
    Render cryptocurrency payment with tap-and-copy functionality using monospace formatting
    
    Args:
        address: Cryptocurrency address
        crypto_name: Display name of cryptocurrency (e.g., "Bitcoin", "Ethereum")
        amount: Optional amount to display
        memo: Optional memo/tag for networks that require it
        order_id: Optional order ID for QR code generation
        expires_minutes: Payment expiration time
        
    Returns:
        Tuple of (message_text, reply_markup) ready for Telegram
    """
    # Import here to avoid circular dependencies
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup
    
    # Format compact message 
    message_parts = []
    
    # Header with amount on same line
    if amount:
        message_parts.append(f"💳 {format_bold(crypto_name)} • 💰 {amount}")
    else:
        message_parts.append(f"💳 {format_bold(crypto_name + ' Deposit')}")
    
    # Address 
    message_parts.append(f"📬 {format_inline_code(address)}")
    
    # Memo if needed
    if memo:
        message_parts.append(f"📋 {format_inline_code(memo)}")
    
    # Compact status line
    if amount:
        message_parts.append(f"💡 Tap to copy • ⏰ {expires_minutes}m • Auto-processed")
    else:
        message_parts.append(f"💡 Tap to copy • ⏰ {expires_minutes}m • Credits wallet")
    
    message_text = "\n".join(message_parts)
    
    # Create keyboard without copy button - use tap-and-copy on address text
    keyboard = []
    
    if memo:
        keyboard.append([InlineKeyboardButton(t('buttons.copy_memo', lang_code), callback_data=f"copy_memo_{memo}")])
    
    # Add QR code button if order_id provided
    if order_id:
        keyboard.append([InlineKeyboardButton(t('buttons.show_qr_code', lang_code), callback_data=f"show_wallet_qr:{order_id}")])
    
    
    return message_text, InlineKeyboardMarkup(keyboard)