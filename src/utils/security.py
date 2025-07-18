"""Security utilities for the application.

This module provides shared security utilities following clean code principles
and eliminating duplication across the codebase.
"""

import hashlib
import secrets
import string
from typing import Optional
import bcrypt
import structlog

from src.common.exceptions import ValidationError
from src.common.i18n import get_translated_message

logger = structlog.get_logger(__name__)


def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure token.
    
    Args:
        length: Length of the token to generate
        
    Returns:
        str: Secure random token
    """
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def hash_password(password: str) -> str:
    """Hash a password using bcrypt.
    
    Args:
        password: Plain text password
        
    Returns:
        str: Hashed password
    """
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def verify_password(password: str, hashed_password: str) -> bool:
    """Verify a password against its hash.
    
    Args:
        password: Plain text password to verify
        hashed_password: Stored password hash
        
    Returns:
        bool: True if password matches, False otherwise
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def validate_token_format(token: str, min_length: int = 8, max_length: int = 128) -> bool:
    """Validate token format and length.
    
    Args:
        token: Token to validate
        min_length: Minimum allowed length
        max_length: Maximum allowed length
        
    Returns:
        bool: True if token format is valid
        
    Raises:
        ValidationError: If token format is invalid
    """
    if not token:
        raise ValidationError("Token cannot be empty")
    
    if len(token) < min_length:
        raise ValidationError(f"Token must be at least {min_length} characters long")
    
    if len(token) > max_length:
        raise ValidationError(f"Token must be no more than {max_length} characters long")
    
    # Check for basic character diversity
    has_letter = any(c.isalpha() for c in token)
    has_digit = any(c.isdigit() for c in token)
    
    if not (has_letter and has_digit):
        raise ValidationError("Token must contain both letters and digits")
    
    return True


def mask_token_for_logging(token: str, visible_chars: int = 8) -> str:
    """Mask a token for secure logging.
    
    Args:
        token: Token to mask
        visible_chars: Number of characters to show
        
    Returns:
        str: Masked token for logging
    """
    if not token or len(token) <= visible_chars:
        return "***"
    
    return f"{token[:visible_chars]}..."


def create_token_hash(token: str) -> str:
    """Create a hash of a token for secure storage.
    
    Args:
        token: Token to hash
        
    Returns:
        str: SHA-256 hash of the token
    """
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def validate_token_ownership(
    token_user_id: int, 
    requesting_user_id: int,
    language: str = "en"
) -> None:
    """Validate that a token belongs to the requesting user.
    
    Args:
        token_user_id: User ID associated with the token
        requesting_user_id: User ID making the request
        language: Language for error messages
        
    Raises:
        ValidationError: If token ownership validation fails
    """
    if token_user_id != requesting_user_id:
        logger.warning(
            "Token ownership validation failed",
            token_user_id=token_user_id,
            requesting_user_id=requesting_user_id
        )
        raise ValidationError(
            get_translated_message("token_ownership_violation", language)
        ) 