"""
Multi-language localization system for HostBay Telegram Bot

Provides comprehensive language support with automatic detection, fallback mechanisms,
and integration with the existing brand configuration system.
"""

import os
import json
import logging
from typing import Dict, Optional, Any, List, Union
from pathlib import Path
from functools import lru_cache

logger = logging.getLogger(__name__)

class LanguageConfig:
    """
    Core language configuration and translation management system
    
    Features:
    - Automatic language detection from Telegram user language_code
    - Fallback to English for missing translations
    - Variable substitution using format() method
    - Extensible architecture for adding new languages
    - Integration with brand configuration system
    """
    
    _instance = None
    _initialized = False
    
    # Supported languages with their display names
    SUPPORTED_LANGUAGES = {
        'en': 'English',
        'fr': 'Français', 
        'es': 'Español'
    }
    
    # Default language fallback chain
    DEFAULT_LANGUAGE = 'en'
    FALLBACK_CHAIN = ['en']  # Always fallback to English
    
    def __new__(cls):
        """Singleton pattern to ensure consistent translation loading"""
        if cls._instance is None:
            cls._instance = super(LanguageConfig, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize language configuration and load translations"""
        if LanguageConfig._initialized:
            return
            
        self.translations: Dict[str, Dict[str, Any]] = {}
        self.locales_path = Path(__file__).parent / 'locales'
        
        # Ensure locales directory exists
        self.locales_path.mkdir(exist_ok=True)
        
        # Load all available translations
        self._load_translations()
        
        LanguageConfig._initialized = True
        logger.info(f"🌍 Language system initialized - Supported: {list(self.SUPPORTED_LANGUAGES.keys())}")
    
    def _load_translations(self) -> None:
        """Load translation files from locales directory"""
        for lang_code in self.SUPPORTED_LANGUAGES.keys():
            translation_file = self.locales_path / f"{lang_code}.json"
            
            try:
                if translation_file.exists():
                    with open(translation_file, 'r', encoding='utf-8') as f:
                        self.translations[lang_code] = json.load(f)
                    logger.debug(f"✅ Loaded translations for {lang_code}")
                else:
                    logger.warning(f"⚠️ Translation file not found: {translation_file}")
                    self.translations[lang_code] = {}
            except Exception as e:
                logger.error(f"❌ Failed to load translations for {lang_code}: {e}")
                self.translations[lang_code] = {}
    
    def reload_translations(self) -> None:
        """Reload all translation files - useful for development"""
        logger.info("🔄 Reloading translation files...")
        self.translations.clear()
        self._load_translations()
    
    def is_language_supported(self, lang_code: str) -> bool:
        """Check if a language code is supported"""
        return lang_code in self.SUPPORTED_LANGUAGES
    
    def get_supported_languages(self) -> Dict[str, str]:
        """Get dictionary of supported language codes and their display names"""
        return self.SUPPORTED_LANGUAGES.copy()
    
    def detect_language_from_telegram(self, telegram_lang_code: Optional[str]) -> str:
        """
        Detect user language from Telegram language_code with fallback logic
        
        Args:
            telegram_lang_code: Language code from Telegram user object (e.g., 'en-US', 'fr', 'es-ES')
            
        Returns:
            Supported language code with fallback to English
        """
        if not telegram_lang_code:
            logger.debug("No Telegram language code provided, using default")
            return self.DEFAULT_LANGUAGE
        
        # Extract base language code (e.g., 'en' from 'en-US')
        base_lang = telegram_lang_code.lower().split('-')[0]
        
        if self.is_language_supported(base_lang):
            logger.debug(f"Detected supported language: {base_lang} from {telegram_lang_code}")
            return base_lang
        
        # Check if it's a regional variant we can map
        language_mappings = {
            'es': ['es', 'es-es', 'es-mx', 'es-ar', 'es-co', 'es-ve'],
            'fr': ['fr', 'fr-fr', 'fr-ca', 'fr-be', 'fr-ch'],
            'en': ['en', 'en-us', 'en-gb', 'en-au', 'en-ca', 'en-ie']
        }
        
        telegram_lang_lower = telegram_lang_code.lower()
        for supported_lang, variants in language_mappings.items():
            if telegram_lang_lower in variants:
                logger.debug(f"Mapped {telegram_lang_code} to {supported_lang}")
                return supported_lang
        
        logger.debug(f"Unsupported language {telegram_lang_code}, falling back to {self.DEFAULT_LANGUAGE}")
        return self.DEFAULT_LANGUAGE
    
    def get_translation(self, key: str, lang_code: str, **kwargs) -> str:
        """
        Get translation for a specific key with variable substitution
        
        Args:
            key: Translation key (e.g., 'welcome.title', 'errors.payment_failed')
            lang_code: Target language code
            **kwargs: Variables for string formatting
            
        Returns:
            Translated string with variables substituted, fallback to English if not found
        """
        # Ensure language is supported
        if not self.is_language_supported(lang_code):
            lang_code = self.DEFAULT_LANGUAGE
        
        # Try to get translation from target language
        translation = self._get_nested_translation(key, lang_code)
        
        # Fallback to English if not found
        if translation is None and lang_code != self.DEFAULT_LANGUAGE:
            translation = self._get_nested_translation(key, self.DEFAULT_LANGUAGE)
            logger.debug(f"Using fallback translation for key '{key}' (lang: {lang_code} -> {self.DEFAULT_LANGUAGE})")
        
        # Final fallback to key itself if no translation found
        if translation is None:
            logger.warning(f"⚠️ No translation found for key '{key}' in any language")
            translation = key
        
        # Apply variable substitution
        try:
            if kwargs:
                return translation.format(**kwargs)
            return translation
        except (KeyError, ValueError) as e:
            logger.warning(f"⚠️ Translation formatting failed for key '{key}': {e}")
            return translation
    
    def _get_nested_translation(self, key: str, lang_code: str) -> Optional[str]:
        """
        Get translation from nested dictionary structure using dot notation
        
        Args:
            key: Dot-separated key (e.g., 'welcome.title')
            lang_code: Language code
            
        Returns:
            Translation string or None if not found
        """
        if lang_code not in self.translations:
            logger.debug(f"🔍 DEBUG: Language {lang_code} not found in translations")
            return None
        
        current = self.translations[lang_code]
        parts = key.split('.')
        
        # DEBUG: Add detailed logging for admin keys
        if key.startswith('admin.'):
            logger.debug(f"🔍 DEBUG: Looking up admin key '{key}' in {lang_code}")
            logger.debug(f"🔍 DEBUG: Path parts: {parts}")
            
        for i, part in enumerate(parts):
            if isinstance(current, dict) and part in current:
                current = current[part]
                if key.startswith('admin.'):
                    logger.debug(f"🔍 DEBUG: Found part '{part}' at level {i}, type: {type(current)}")
            else:
                if key.startswith('admin.'):
                    logger.debug(f"🔍 DEBUG: Missing part '{part}' at level {i}")
                    if isinstance(current, dict):
                        available_keys = list(current.keys())[:10]  # Show first 10 keys
                        logger.debug(f"🔍 DEBUG: Available keys at this level: {available_keys}")
                return None
        
        result = current if isinstance(current, str) else None
        if key.startswith('admin.'):
            logger.debug(f"🔍 DEBUG: Final result for '{key}': {result is not None} - {result[:50] if result else 'None'}...")
        
        return result
    
    def get_available_translations_for_key(self, key: str) -> Dict[str, str]:
        """
        Get all available translations for a specific key
        
        Args:
            key: Translation key
            
        Returns:
            Dictionary mapping language codes to translations
        """
        results = {}
        for lang_code in self.SUPPORTED_LANGUAGES.keys():
            translation = self._get_nested_translation(key, lang_code)
            if translation is not None:
                results[lang_code] = translation
        return results


# Global instance for easy access
_language_config = None

def get_language_config() -> LanguageConfig:
    """Get the global LanguageConfig instance"""
    global _language_config
    if _language_config is None:
        _language_config = LanguageConfig()
    return _language_config


# Convenience functions for common operations

def detect_user_language(telegram_lang_code: Optional[str]) -> str:
    """
    Detect user language from Telegram language code (synchronous fallback)
    
    Args:
        telegram_lang_code: Language code from Telegram user
        
    Returns:
        Supported language code
    """
    config = get_language_config()
    return config.detect_language_from_telegram(telegram_lang_code)


# Enhanced translation functions with user context

async def t_for_user(key: str, telegram_id: int, telegram_lang_code: Optional[str] = None, explicit_lang_code: Optional[str] = None, **kwargs) -> str:
    """
    Get localized translation for a specific user using complete language resolution
    
    Args:
        key: Translation key (e.g., 'welcome.title')
        telegram_id: Telegram user ID
        telegram_lang_code: Language code from Telegram user object (optional)
        explicit_lang_code: Explicitly requested language code (optional)
        **kwargs: Variables for string formatting
        
    Returns:
        Localized string with variables substituted
    
    Example:
        await t_for_user('welcome.greeting', user_id, user.language_code, username='John')
    """
    resolved_lang = await resolve_user_language(telegram_id, telegram_lang_code, explicit_lang_code)
    return t(key, resolved_lang, **kwargs)


async def set_and_get_user_language(telegram_id: int, lang_code: str) -> str:
    """
    Set user language preference and return the resolved language
    
    Args:
        telegram_id: Telegram user ID
        lang_code: Language code to set
        
    Returns:
        The resolved language code (may be default if setting failed)
    """
    success = await set_user_language_preference(telegram_id, lang_code)
    if success:
        return lang_code
    else:
        # If setting failed, fall back to current resolution
        return await resolve_user_language(telegram_id)


def is_language_supported(lang_code: str) -> bool:
    """Check if a language is supported"""
    config = get_language_config()
    return config.is_language_supported(lang_code)


def get_supported_languages() -> Dict[str, str]:
    """Get all supported languages"""
    config = get_language_config()
    return config.get_supported_languages()


def reload_translations() -> None:
    """Reload all translation files"""
    config = get_language_config()
    config.reload_translations()


# Translation function - main interface for getting localized strings
def t(key: str, lang_code: str = 'en', **kwargs) -> str:
    """
    Main translation function - get localized string with variable substitution
    
    Args:
        key: Translation key (e.g., 'welcome.title')
        lang_code: Target language code (defaults to English)
        **kwargs: Variables for string formatting
        
    Returns:
        Localized string with variables substituted
    
    Example:
        t('welcome.greeting', 'fr', username='Jean')
        t('errors.payment_failed', 'es', amount='50.00', currency='EUR')
    """
    config = get_language_config()
    return config.get_translation(key, lang_code, **kwargs)


# Advanced translation functions

def t_with_fallback(key: str, lang_code: str, fallback_text: str, **kwargs) -> str:
    """
    Get translation with custom fallback text
    
    Args:
        key: Translation key
        lang_code: Target language code
        fallback_text: Custom fallback text if translation not found
        **kwargs: Variables for string formatting
        
    Returns:
        Localized string or custom fallback
    """
    config = get_language_config()
    translation = config._get_nested_translation(key, lang_code)
    
    if translation is None:
        translation = fallback_text
    
    try:
        if kwargs:
            return translation.format(**kwargs)
        return translation
    except (KeyError, ValueError):
        return translation


def t_pluralize(key_singular: str, key_plural: str, count: int, lang_code: str = 'en', **kwargs) -> str:
    """
    Get pluralized translation based on count
    
    Args:
        key_singular: Translation key for singular form
        key_plural: Translation key for plural form  
        count: Number to determine singular/plural
        lang_code: Target language code
        **kwargs: Variables for string formatting (count is automatically added)
        
    Returns:
        Appropriate singular/plural translation
    """
    key = key_singular if count == 1 else key_plural
    kwargs['count'] = count
    return t(key, lang_code, **kwargs)


def t_list(keys: List[str], lang_code: str = 'en', **kwargs) -> List[str]:
    """
    Get multiple translations at once
    
    Args:
        keys: List of translation keys
        lang_code: Target language code
        **kwargs: Variables for string formatting
        
    Returns:
        List of translated strings
    """
    return [t(key, lang_code, **kwargs) for key in keys]


# Language preference management with complete resolution chain

async def resolve_user_language(telegram_id: int, telegram_lang_code: Optional[str] = None, explicit_lang_code: Optional[str] = None) -> str:
    """
    Resolve user's language with proper fallback chain
    
    Priority order:
    1. User setting (explicit language change request)
    2. Stored preference (from database)  
    3. Telegram language (from user's Telegram client)
    4. Default (English)
    
    Args:
        telegram_id: Telegram user ID
        telegram_lang_code: Language code from Telegram user object (optional)
        explicit_lang_code: Explicitly requested language code (optional)
        
    Returns:
        Resolved language code following priority chain
    """
    config = get_language_config()
    
    # 1. PRIORITY 1: Explicit user setting (highest priority)
    if explicit_lang_code:
        if config.is_language_supported(explicit_lang_code):
            logger.debug(f"Using explicit language setting for user {telegram_id}: {explicit_lang_code}")
            return explicit_lang_code
        else:
            logger.warning(f"Explicit language {explicit_lang_code} not supported, falling back to next priority")
    
    # 2. PRIORITY 2: Stored user preference from database
    try:
        stored_preference = await get_user_language_preference(telegram_id)
        if stored_preference != LanguageConfig.DEFAULT_LANGUAGE:
            # We have a valid stored preference (not the default fallback)
            logger.debug(f"Using stored language preference for user {telegram_id}: {stored_preference}")
            return stored_preference
    except Exception as e:
        logger.debug(f"Could not retrieve stored language preference for user {telegram_id}: {e}")
    
    # 3. PRIORITY 3: Telegram client language
    if telegram_lang_code:
        detected_lang = config.detect_language_from_telegram(telegram_lang_code)
        if detected_lang != LanguageConfig.DEFAULT_LANGUAGE:
            # Telegram language was successfully mapped to a supported language
            logger.debug(f"Using Telegram language for user {telegram_id}: {detected_lang} (from {telegram_lang_code})")
            return detected_lang
    
    # 4. PRIORITY 4: Default language (final fallback)
    logger.debug(f"Using default language for user {telegram_id}: {LanguageConfig.DEFAULT_LANGUAGE}")
    return LanguageConfig.DEFAULT_LANGUAGE


async def get_user_language_preference(telegram_id: int) -> str:
    """
    Get user's language preference from database with caching OPTIMIZED
    
    Args:
        telegram_id: Telegram user ID
        
    Returns:
        User's preferred language code (defaults to 'en' if not set)
    """
    from performance_cache import performance_cache
    from database import execute_query
    import time
    
    start_time = time.perf_counter()
    
    # Try cache first
    cache_key = f"user_lang:{telegram_id}"
    cached_lang = performance_cache.get(cache_key, 'user_language')
    if cached_lang:
        elapsed = (time.perf_counter() - start_time) * 1000
        logger.debug(f"⚡ LANG CACHE HIT: {telegram_id} in {elapsed:.1f}ms")
        return cached_lang
    
    try:
        result = await execute_query(
            "SELECT preferred_language FROM users WHERE telegram_id = %s",
            (telegram_id,)
        )
        
        lang_code = LanguageConfig.DEFAULT_LANGUAGE  # Default fallback
        
        if result and result[0]['preferred_language']:
            stored_lang = result[0]['preferred_language']
            if is_language_supported(stored_lang):
                lang_code = stored_lang
                logger.debug(f"Retrieved language preference for user {telegram_id}: {lang_code}")
            else:
                logger.debug(f"Invalid stored language {stored_lang} for user {telegram_id}, using default")
        else:
            logger.debug(f"No language preference found for user {telegram_id}, using default")
        
        # Cache the result (even if default) for 30 minutes
        performance_cache.set(cache_key, lang_code, 'user_language', ttl=1800)
        
        elapsed = (time.perf_counter() - start_time) * 1000
        logger.info(f"⚡ LANG DB QUERY: {telegram_id} in {elapsed:.1f}ms (cached 30min)")
        
        return lang_code
        
    except Exception as e:
        logger.debug(f"Could not get user language preference for {telegram_id}: {e}")
        # Cache the default to avoid repeated DB failures
        performance_cache.set(cache_key, LanguageConfig.DEFAULT_LANGUAGE, 'user_language', ttl=300)
        return LanguageConfig.DEFAULT_LANGUAGE


async def set_user_language_preference(telegram_id: int, lang_code: str) -> bool:
    """
    Set user's language preference in database and invalidate cache
    
    Args:
        telegram_id: Telegram user ID
        lang_code: Language code to set
        
    Returns:
        True if successful, False otherwise
    """
    if not is_language_supported(lang_code):
        logger.warning(f"Attempted to set unsupported language: {lang_code}")
        return False
    
    from database import execute_update
    from performance_cache import cache_invalidate
    
    try:
        # Update database
        rows_affected = await execute_update(
            "UPDATE users SET preferred_language = %s WHERE telegram_id = %s",
            (lang_code, telegram_id)
        )
        
        if rows_affected > 0:
            # Invalidate cache immediately after successful DB update
            cache_invalidate('user_language', user_id=telegram_id)
            logger.info(f"✅ Updated language preference for user {telegram_id}: {lang_code} (cache invalidated)")
            return True
        else:
            logger.warning(f"⚠️ User {telegram_id} not found when setting language preference")
            return False
    except Exception as e:
        logger.error(f"❌ Failed to set language preference for user {telegram_id}: {e}")
        return False


# Utility functions for translation management

def validate_translation_keys(lang_code: str) -> Dict[str, Any]:
    """
    Validate translation file structure and find missing keys
    
    Args:
        lang_code: Language code to validate
        
    Returns:
        Validation report with missing keys and statistics
    """
    config = get_language_config()
    
    if not config.is_language_supported(lang_code):
        return {'error': f'Unsupported language: {lang_code}'}
    
    # Get English translations as reference
    en_translations = config.translations.get('en', {})
    target_translations = config.translations.get(lang_code, {})
    
    def get_all_keys(d: Dict, prefix: str = '') -> List[str]:
        """Recursively get all translation keys"""
        keys = []
        for key, value in d.items():
            current_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                keys.extend(get_all_keys(value, current_key))
            elif isinstance(value, str):
                keys.append(current_key)
        return keys
    
    en_keys = set(get_all_keys(en_translations))
    target_keys = set(get_all_keys(target_translations))
    
    missing_keys = en_keys - target_keys
    extra_keys = target_keys - en_keys
    
    return {
        'language': lang_code,
        'total_en_keys': len(en_keys),
        'total_target_keys': len(target_keys),
        'missing_keys': sorted(list(missing_keys)),
        'extra_keys': sorted(list(extra_keys)),
        'completion_percentage': (len(target_keys) / len(en_keys) * 100) if en_keys else 0
    }


def get_translation_statistics() -> Dict[str, Any]:
    """
    Get comprehensive translation statistics for all languages
    
    Returns:
        Statistics report for translation completion
    """
    config = get_language_config()
    stats = {}
    
    for lang_code in config.SUPPORTED_LANGUAGES.keys():
        stats[lang_code] = validate_translation_keys(lang_code)
    
    return stats


# ====================================================================
# CRITICAL SECURITY: HTML-SAFE TRANSLATION HELPER
# ====================================================================

def t_html(key: str, lang_code: str = 'en', **kwargs) -> tuple[str, str]:
    """
    SECURE HTML translation helper with automatic escaping and parse_mode enforcement.
    
    This function addresses critical security issues by:
    1. Automatically escaping ALL user-controlled variables to prevent HTML injection
    2. Ensuring parse_mode=HTML is always enforced for HTML content
    3. Providing a consistent API for secure localized HTML content
    
    Args:
        key: Translation key (e.g., 'welcome.greeting', 'errors.payment_failed')
        lang_code: Target language code
        **kwargs: Variables for translation formatting - ALL will be HTML-escaped automatically
        
    Returns:
        Tuple of (html_safe_content, parse_mode) where:
        - html_safe_content: Translated text with user variables HTML-escaped
        - parse_mode: Always 'HTML' to ensure proper parsing
        
    Example:
        # Safe usage with user-controlled data
        user_name = "<script>alert('xss')</script>"  # Malicious input
        domain_name = "example<b>.com"               # User input with HTML
        
        text, parse_mode = t_html('welcome.greeting', 'en', 
                                 platform_name='HostBay',        # Safe - system controlled
                                 user_name=user_name,            # Unsafe - will be escaped
                                 domain=domain_name)             # Unsafe - will be escaped
        
        await query.edit_message_text(text, parse_mode=parse_mode)  # Always HTML mode
        
    Security guarantees:
    - All kwargs values are HTML-escaped before string formatting
    - Result is safe for use with parse_mode=HTML
    - No user input can inject HTML tags or break formatting
    - XSS attacks through translation variables are prevented
    """
    try:
        # Import HTML escaping functions
        from message_utils import escape_html
        
        # Step 1: HTML escape ALL user-provided variables
        safe_kwargs = {}
        for var_name, var_value in kwargs.items():
            if var_value is not None:
                # Convert to string and escape HTML special characters
                safe_kwargs[var_name] = escape_html(str(var_value))
            else:
                safe_kwargs[var_name] = ""
        
        # Step 2: Get the translated template
        config = get_language_config()
        if config:
            try:
                translated_template = config.get_translation(key, lang_code, **safe_kwargs)
            except Exception as template_error:
                logger.error(f"Translation template error for key '{key}' in '{lang_code}': {template_error}")
                # Fallback to key name, but still escaped
                translated_template = escape_html(key)
        else:
            logger.warning("Language config not available, using key as fallback")
            translated_template = escape_html(key)
        
        # Step 3: Return safe HTML content with enforced parse mode
        return translated_template, 'HTML'
        
    except Exception as e:
        logger.error(f"Critical error in t_html() for key '{key}': {e}")
        # Emergency fallback - return escaped key with safe parse mode
        try:
            from message_utils import escape_html
            return escape_html(key), 'HTML'
        except ImportError:
            # Ultimate fallback if message_utils unavailable
            import html
            return html.escape(key), 'HTML'


async def t_html_for_user(key: str, user_id: int, telegram_lang_code: Optional[str] = None, **kwargs) -> tuple[str, str]:
    """
    User-context HTML-safe translation with automatic language resolution.
    
    Combines user language resolution with secure HTML translation for maximum
    security and usability.
    
    Args:
        key: Translation key
        user_id: Telegram user ID for language resolution
        telegram_lang_code: Optional Telegram language code
        **kwargs: Variables for translation formatting - ALL will be HTML-escaped
        
    Returns:
        Tuple of (html_safe_content, parse_mode) - Always ('content', 'HTML')
        
    Example:
        text, parse_mode = await t_html_for_user('welcome.greeting', user_id=12345, 
                                               user_name=update.effective_user.first_name)
        await query.edit_message_text(text, parse_mode=parse_mode)
    """
    try:
        # Resolve user's preferred language
        user_lang = await resolve_user_language(user_id, telegram_lang_code)
        
        # Use secure HTML translation
        return t_html(key, user_lang, **kwargs)
        
    except Exception as e:
        logger.error(f"Error in t_html_for_user() for user {user_id}, key '{key}': {e}")
        # Fallback to English with HTML safety
        return t_html(key, 'en', **kwargs)