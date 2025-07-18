"""Password Value Objects for domain modeling.

These value objects encapsulate password-related business rules and validation logic,
ensuring password strength requirements are enforced consistently across the domain.
"""

import re
import bcrypt
from dataclasses import dataclass
from typing import ClassVar, Optional
from src.common.exceptions import PasswordPolicyError
from src.common.i18n import get_translated_message


def _hash_password(password: str) -> str:
    """Hash a password using bcrypt.
    
    Args:
        password: Plain text password
        
    Returns:
        str: Hashed password
    """
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def _verify_password(password: str, hashed_password: str) -> bool:
    """Verify a password against its hash.
    
    Args:
        password: Plain text password to verify
        hashed_password: Stored password hash
        
    Returns:
        bool: True if password matches, False otherwise
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


@dataclass(frozen=True)
class LoginPassword:
    """Password value object for login attempts with minimal validation.
    
    This value object is specifically designed for login attempts and only
    performs basic format validation without applying password policy rules.
    This prevents false positives during authentication.
    
    Security Requirements:
        - Not empty
        - Reasonable length (1-128 characters)
        
    Attributes:
        value: The raw password string (immutable)
    """
    
    value: str
    
    # Basic constraints for login
    MIN_LENGTH: ClassVar[int] = 1
    MAX_LENGTH: ClassVar[int] = 128
    
    def __post_init__(self) -> None:
        """Validate password on construction."""
        self._validate()
    
    def _validate(self) -> None:
        """Validate password with minimal requirements for login.
        
        Raises:
            ValueError: If password doesn't meet basic requirements
        """
        if not self.value:
            raise ValueError("Password cannot be empty")
        
        if len(self.value) < self.MIN_LENGTH:
            raise ValueError(f"Password must be at least {self.MIN_LENGTH} character long")
        
        if len(self.value) > self.MAX_LENGTH:
            raise ValueError(f"Password must not exceed {self.MAX_LENGTH} characters")
    
    def verify_against_hash(self, hashed_password: str) -> bool:
        """Verify this password against a bcrypt hash using constant-time comparison.
        
        This method provides secure password verification by delegating to the
        security utility function that uses bcrypt's built-in constant-time
        comparison to prevent timing attacks.
        
        Args:
            hashed_password: The bcrypt hash to verify against
            
        Returns:
            bool: True if password matches the hash, False otherwise
            
        Security Features:
            - Constant-time comparison via bcrypt
            - Resistant to timing attacks
            - Uses same bcrypt configuration as password hashing
            - Handles bcrypt hash format validation internally
            - Returns False for any invalid hash format (no information disclosure)
        """
        try:
            return _verify_password(self.value, hashed_password)
        except Exception:
            # Return False for any invalid hash format or verification error
            # This prevents information disclosure through error messages
            # and ensures consistent behavior regardless of hash validity
            return False


@dataclass(frozen=True)
class Password:
    """Password value object that enforces security requirements.
    
    This value object encapsulates all password validation rules and ensures
    that only valid passwords can be created. It follows the fail-fast principle
    by validating on construction.
    
    Security Requirements:
        - Minimum 8 characters
        - Maximum 128 characters  
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        
    Attributes:
        value: The raw password string (immutable)
    """
    
    value: str
    language: str = "en"
    
    # Security constraints as class constants
    MIN_LENGTH: ClassVar[int] = 8
    MAX_LENGTH: ClassVar[int] = 128
    REQUIRED_UPPERCASE: ClassVar[int] = 1
    REQUIRED_LOWERCASE: ClassVar[int] = 1
    REQUIRED_DIGITS: ClassVar[int] = 1
    REQUIRED_SPECIAL: ClassVar[int] = 1
    SPECIAL_CHARS: ClassVar[str] = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    def __post_init__(self) -> None:
        """Validate password on construction."""
        self._validate()
    
    def _validate(self) -> None:
        """Validate password against all security requirements.
        
        Raises:
            PasswordPolicyError: If password doesn't meet security requirements
        """
        if not self.value:
            raise PasswordPolicyError(get_translated_message("password_empty", self.language))
        
        if len(self.value) < self.MIN_LENGTH:
            raise PasswordPolicyError(get_translated_message("password_too_short", self.language).format(length=self.MIN_LENGTH))
        
        if len(self.value) > self.MAX_LENGTH:
            raise PasswordPolicyError(get_translated_message("password_too_long", self.language).format(max_length=self.MAX_LENGTH))
        
        # Check character requirements
        if not re.search(r"[A-Z]", self.value):
            raise PasswordPolicyError(get_translated_message("password_no_uppercase", self.language))
        
        if not re.search(r"[a-z]", self.value):
            raise PasswordPolicyError(get_translated_message("password_no_lowercase", self.language))
        
        if not re.search(r"\d", self.value):
            raise PasswordPolicyError(get_translated_message("password_no_digit", self.language))
        
        if not any(char in self.SPECIAL_CHARS for char in self.value):
            raise PasswordPolicyError(get_translated_message("password_no_special_char", self.language))
        
        # Check for common weak patterns
        if self._contains_weak_patterns():
            raise PasswordPolicyError(get_translated_message("password_too_weak", self.language))
    
    def _contains_weak_patterns(self) -> bool:
        """Check for common weak password patterns.
        
        Returns:
            bool: True if password contains weak patterns
        """
        weak_patterns = [
            r"(.)\1{2,}",  # Three or more consecutive identical characters
            r"123|234|345|456|567|678|789|890",  # Sequential numbers
            r"abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz",  # Sequential letters
            r"password|admin|user|login|welcome|secret",  # Common words (case-insensitive)
        ]
        
        for pattern in weak_patterns:
            if re.search(pattern, self.value.lower()):
                return True
        
        return False
    
    def verify_against_hash(self, hashed_password: str) -> bool:
        """Verify this password against a bcrypt hash using constant-time comparison.
        
        This method provides secure password verification by delegating to the
        security utility function that uses bcrypt's built-in constant-time
        comparison to prevent timing attacks.
        
        Args:
            hashed_password: The bcrypt hash to verify against
            
        Returns:
            bool: True if password matches the hash, False otherwise
            
        Security Features:
            - Constant-time comparison via bcrypt
            - Resistant to timing attacks
            - Uses same bcrypt configuration as password hashing
            - Handles bcrypt hash format validation internally
            - Returns False for any invalid hash format (no information disclosure)
            
        Example:
            >>> password = Password("SecurePass123!")
            >>> hashed = "$2b$12$..."  # From database
            >>> is_valid = password.verify_against_hash(hashed)
        """
        try:
            return _verify_password(self.value, hashed_password)
        except Exception:
            # Return False for any invalid hash format or verification error
            # This prevents information disclosure through error messages
            # and ensures consistent behavior regardless of hash validity
            return False
    
    def to_hashed(self) -> 'HashedPassword':
        """Convert password to hashed format for secure storage.
        
        Returns:
            HashedPassword: Securely hashed password value object
        """
        hashed_value = _hash_password(self.value)
        return HashedPassword(value=hashed_value)


@dataclass(frozen=True)
class HashedPassword:
    """Hashed password value object.
    
    Represents a securely hashed password that can be safely stored.
    This value object ensures passwords are always properly hashed
    before storage and supports both legacy unencrypted and new encrypted storage.
    
    Attributes:
        value: The hashed password string (immutable)
    """
    
    value: str
    
    def __post_init__(self) -> None:
        """Validate hashed password format."""
        if not self.value:
            raise ValueError("Hashed password cannot be empty")
        
        # Basic bcrypt or encrypted format validation
        is_bcrypt = self.value.startswith("$2b$") and len(self.value) == 60
        is_encrypted = self.value.startswith("enc_v1:") and len(self.value) > len("enc_v1:")

        if not (is_bcrypt or is_encrypted):
            raise ValueError("Invalid hashed password format")
    
    def verify_plain_password(self, plain_password: str) -> bool:
        """Verify a plain password against this hash.
        
        Args:
            plain_password: Plain text password to verify
            
        Returns:
            bool: True if password matches the hash
        """
        return _verify_password(plain_password, self.value)
    
    def is_encrypted(self) -> bool:
        """Check if this hash is encrypted (has enc_v1: prefix).
        
        Returns:
            bool: True if hash is encrypted
        """
        return self.value.startswith("enc_v1:")
    
    @classmethod
    def from_plain_password(cls, password: Password) -> 'HashedPassword':
        """Create hashed password from plain password.
        
        Args:
            password: Password value object
            
        Returns:
            HashedPassword: Hashed password
        """
        hashed_value = _hash_password(password.value)
        return cls(value=hashed_value)
    
    @classmethod
    def from_hash(cls, hashed_value: str) -> 'HashedPassword':
        """Create hashed password from existing hash.
        
        Args:
            hashed_value: Existing hash string
            
        Returns:
            HashedPassword: Hashed password object
        """
        return cls(value=hashed_value)


@dataclass(frozen=True)
class EncryptedPassword:
    """Encrypted password value object for defense-in-depth security.
    
    This value object represents a password that has been both hashed (bcrypt) and 
    encrypted (AES) for storage. It provides an additional security layer beyond
    bcrypt hashing to protect against database compromise scenarios.
    
    Security Features:
        - Two-layer protection: bcrypt + AES encryption
        - Migration compatibility with legacy unencrypted hashes
        - Immutable design prevents accidental modification
        - Clear separation between encrypted and unencrypted formats
        
    Attributes:
        encrypted_value: The encrypted bcrypt hash (with enc_v1: prefix)
    """
    
    encrypted_value: str
    
    def __post_init__(self) -> None:
        """Validate encrypted password format."""
        if not self.encrypted_value:
            raise ValueError("Encrypted password cannot be empty")
        
        if not self.encrypted_value.startswith("enc_v1:"):
            raise ValueError("Invalid encrypted password format")
    
    @classmethod
    async def from_hashed_password(
        cls, 
        hashed_password: HashedPassword, 
        encryption_service: 'IPasswordEncryptionService'
    ) -> 'EncryptedPassword':
        """Create encrypted password from hashed password.
        
        Args:
            hashed_password: Hashed password to encrypt
            encryption_service: Service for encryption
            
        Returns:
            EncryptedPassword: Encrypted password
        """
        if hashed_password.is_encrypted():
            return cls(encrypted_value=hashed_password.value)

        encrypted_value = await encryption_service.encrypt(hashed_password.value)
        return cls(encrypted_value=encrypted_value)
    
    async def to_bcrypt_hash(
        self, 
        encryption_service: 'IPasswordEncryptionService'
    ) -> str:
        """Decrypt to bcrypt hash for verification.
        
        Args:
            encryption_service: Service for decryption
            
        Returns:
            str: Decrypted bcrypt hash
        """
        return await encryption_service.decrypt(self.encrypted_value)
    
    def get_storage_value(self) -> str:
        """Get the value to store in database.
        
        Returns:
            str: Encrypted value for storage
        """
        return self.encrypted_value
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return f"EncryptedPassword(encrypted_value='{self.encrypted_value[:10]}...')" 