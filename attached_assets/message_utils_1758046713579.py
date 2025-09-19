"""
Message formatting and escaping utilities for HostBay Telegram Bot

Provides consistent HTML formatting and escaping for all bot messages
to prevent parsing errors and improve robustness.
"""

import re
import html
from typing import Tuple, Optional


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


# Brand-specific formatting helpers
def get_support_username() -> str:
    """Get the properly formatted support username."""
    return escape_username("@Hostbay_support")


def get_platform_name() -> str:
    """Get the properly formatted platform name."""
    return escape_html("HostBay")


# Common message templates
def create_contact_support_message(platform_name: str, user_id: int) -> str:
    """
    Create the contact support message with proper HTML formatting.
    
    Args:
        platform_name: Name of the platform
        user_id: User's Telegram ID
        
    Returns:
        Properly formatted contact support message
    """
    message = f"""💬 {format_bold("Contact Support")}

{get_support_username()}

{format_bold("Help with:")} payments, domains, DNS, hosting, wallets, technical issues

{format_bold("Response time:")} few hours during business hours

{format_bold("Your ID:")} {format_inline_code(str(user_id))}"""
    
    return message