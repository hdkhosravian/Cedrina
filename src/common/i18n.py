"""
Common internationalization (i18n) utility module for handling translations and language preferences.

This module provides functionality for:
- Loading and managing translations for multiple languages
- Translating messages based on user preferences
- Determining user language from headers or parameters
- Fallback mechanisms for missing translations

This module must not import from any higher-level modules (core, settings, logger, etc.).
"""

import gettext
import os
from typing import Dict, Optional

# Store translations for each language
_translations: Dict[str, gettext.GNUTranslations] = {}
_fallback_catalogs: Dict[str, Dict[str, str]] = {}

# These must be set by the application at startup
SUPPORTED_LANGUAGES = ["en"]
DEFAULT_LANGUAGE = "en"
LOCALES_PATH = None  # Must be set to the absolute path of the locales directory

def setup_i18n(locales_path: str, supported_languages: list, default_language: str) -> None:
    """Initialize the internationalization system by loading translations."""
    global SUPPORTED_LANGUAGES, DEFAULT_LANGUAGE, LOCALES_PATH
    SUPPORTED_LANGUAGES = supported_languages
    DEFAULT_LANGUAGE = default_language
    LOCALES_PATH = locales_path

    if not os.path.exists(locales_path):
        raise FileNotFoundError(f"Locales directory not found: {locales_path}")

    for lang in SUPPORTED_LANGUAGES:
        translation = gettext.translation(
            domain="messages",
            localedir=locales_path,
            languages=[lang],
            fallback=True,
        )
        _translations[lang] = translation

        # Parse .po file as fallback for newly added translations not in .mo
        po_path = os.path.join(locales_path, lang, "LC_MESSAGES", "messages.po")
        catalog: Dict[str, str] = {}
        if os.path.exists(po_path):
            try:
                file_size = os.path.getsize(po_path)
                if file_size > 10 * 1024 * 1024:
                    continue
                with open(po_path, encoding="utf-8") as po_file:
                    current_msgid: Optional[str] = None
                    for raw_line in po_file:
                        line = raw_line.strip()
                        if line.startswith("msgid "):
                            current_msgid = line[6:].strip().strip('"')
                        elif line.startswith("msgstr ") and current_msgid is not None:
                            msgstr = line[7:].strip().strip('"')
                            catalog[current_msgid] = msgstr or current_msgid
                            current_msgid = None
            except Exception:
                pass
        _fallback_catalogs[lang] = catalog


def get_translated_message(key: str, locale: str = None) -> str:
    """Retrieve a translated message for the given key and locale."""
    locale = locale or DEFAULT_LANGUAGE
    if locale not in _translations:
        locale = DEFAULT_LANGUAGE
    translation = _translations.get(locale)
    if not translation:
        return key
    translated = translation.gettext(key)
    if translated == key:
        catalog = _fallback_catalogs.get(locale, {})
        translated = catalog.get(key, key)
    return translated


def get_request_language(
    lang_param: Optional[str] = None,
    accept_language_header: Optional[str] = None
) -> str:
    """Determine the preferred language from parameters or headers.
    Args:
        lang_param: Query parameter or explicit language code
        accept_language_header: Value of Accept-Language header
    Returns:
        The determined language code.
    """
    if lang_param and lang_param in SUPPORTED_LANGUAGES:
        return lang_param
    if accept_language_header:
        for lang in accept_language_header.split(","):
            lang = lang.split(";")[0].strip().split("-")[0]
            if lang in SUPPORTED_LANGUAGES:
                return lang
    return DEFAULT_LANGUAGE


def extract_language_from_request(request) -> str:
    """Extract language from request parameters and headers in a centralized way.
    
    This function follows DRY principles by centralizing the language extraction
    logic that was previously duplicated across all API routes.
    
    Args:
        request: FastAPI request object or any object with query_params and headers
        
    Returns:
        str: The determined language code
    """
    lang_param = request.query_params.get("lang")
    accept_language_header = request.headers.get("Accept-Language")
    return get_request_language(lang_param, accept_language_header) 