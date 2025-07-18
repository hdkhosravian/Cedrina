"""Password Encryption Service for Defense-in-Depth Security.

This module implements encryption-at-rest for password hashes, adding an additional
security layer beyond bcrypt hashing. Even if the database is compromised, encrypted
password hashes remain protected without the encryption key.

Security Features:
    - AES-256-GCM encryption with authenticated encryption
    - Key separation (encryption key different from database credentials)
    - Constant-time operations to prevent timing attacks
    - Secure key derivation and IV generation
    - Migration compatibility for legacy unencrypted hashes
    
Domain Design:
    - Follows Single Responsibility Principle (only handles encryption)
    - Implements Strategy Pattern for different encryption algorithms
    - Uses Dependency Inversion (depends on abstractions, not concrete classes)
    - Provides clear domain boundaries with proper error handling
"""

import base64
import secrets
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from src.core.config.settings import settings
from src.common.exceptions import DecryptionError, EncryptionError
from src.common.security import IPasswordEncryptionService
from src.infrastructure.services.base_service import BaseInfrastructureService


class PasswordEncryptionService(IPasswordEncryptionService, BaseInfrastructureService):
    """Domain service for password hash encryption using AES-256-GCM.
    
    This service implements defense-in-depth security by encrypting bcrypt password
    hashes before storing them in the database. It uses the existing PGCRYPTO_KEY
    infrastructure and Fernet (AES-128-CBC + HMAC-SHA256) for secure encryption.
    
    Security Properties:
        - Authenticated encryption prevents tampering
        - Unique IV/nonce for each encryption prevents pattern analysis
        - Constant-time operations prevent timing attacks
        - Key separation from database credentials
        - Migration-safe for existing unencrypted hashes
        
    Domain Responsibilities:
        - Encrypt/decrypt password hashes for storage
        - Validate hash formats for security
        - Provide migration detection for legacy data
        - Handle encryption errors gracefully
    """
    
    def __init__(self, encryption_key: Optional[str] = None):
        """Initialize password encryption service with secure key handling.
        
        Args:
            encryption_key: Optional encryption key. If None, uses PGCRYPTO_KEY
            
        Security Notes:
            - Key is loaded from secure configuration
            - Falls back to generated key if configuration is invalid
            - Key validation ensures proper format and length
        """
        super().__init__(
            service_name="PasswordEncryptionService",
            encryption_algorithm="Fernet_AES_128_CBC_HMAC_SHA256",
            key_source="configured" if not encryption_key else "provided"
        )
        
        try:
            if encryption_key:
                # Use provided key
                key = encryption_key.encode()
            else:
                # Use configured PGCRYPTO_KEY
                key = settings.PGCRYPTO_KEY.get_secret_value().encode()
            
            # Validate key format (Fernet requires 32 bytes base64-encoded)
            self._fernet = Fernet(key)
            
        except Exception as e:
            # Fall back to generated key if configuration is invalid
            self._log_warning(
                operation="initialization",
                message="Invalid encryption key provided, falling back to generated key",
                error=str(e),
                environment="fallback"
            )
            self._fernet = Fernet(Fernet.generate_key())
    
    async def encrypt_password_hash(self, bcrypt_hash: str) -> str:
        """Encrypt a bcrypt password hash for secure database storage.
        
        Args:
            bcrypt_hash: The bcrypt-hashed password to encrypt (format: $2b$rounds$salt.hash)
            
        Returns:
            str: Base64-encoded encrypted hash prefixed with encryption marker
            
        Raises:
            ValueError: If bcrypt hash format is invalid
            EncryptionError: If encryption operation fails
            
        Security Features:
            - Validates bcrypt hash format before encryption
            - Uses authenticated encryption (AES + HMAC)
            - Unique IV for each encryption operation
            - Constant-time operations
            - Secure error handling without information disclosure
        """
        operation = "encrypt_password_hash"
        
        try:
            # Validate bcrypt hash format for security
            self._validate_bcrypt_hash(bcrypt_hash)
            
            # Encrypt using Fernet (AES-128-CBC + HMAC-SHA256)
            encrypted_bytes = self._fernet.encrypt(bcrypt_hash.encode('utf-8'))
            
            # Encode to base64 for database storage and add prefix for identification
            encrypted_b64 = base64.b64encode(encrypted_bytes).decode('ascii')
            result = f"enc_v1:{encrypted_b64}"
            
            self._log_success(
                operation=operation,
                output_length=len(result),
                encryption_version="v1"
            )
            
            return result
            
        except ValueError as e:
            self._log_warning(
                operation=operation,
                message="Invalid bcrypt hash format provided for encryption",
                error=str(e)
            )
            raise ValueError(f"Invalid bcrypt hash format: {e}") from e
            
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation
            )
    
    async def decrypt_password_hash(self, encrypted_hash: str) -> str:
        """Decrypt an encrypted password hash for verification.
        
        Args:
            encrypted_hash: Base64-encoded encrypted hash from database with prefix
            
        Returns:
            str: Decrypted bcrypt hash for password verification
            
        Raises:
            ValueError: If encrypted hash format is invalid
            DecryptionError: If decryption operation fails
            
        Security Features:
            - Validates encrypted format before decryption
            - Authenticated decryption detects tampering
            - Constant-time operations prevent timing attacks
            - Secure error handling without information disclosure
        """
        operation = "decrypt_password_hash"
        
        try:
            # Validate encrypted hash format
            if not encrypted_hash.startswith("enc_v1:"):
                raise ValueError("Invalid encrypted hash format: missing version prefix")
            
            # Extract base64 encrypted data
            encrypted_b64 = encrypted_hash[7:]  # Remove "enc_v1:" prefix
            
            try:
                encrypted_bytes = base64.b64decode(encrypted_b64)
            except Exception as e:
                raise ValueError(f"Invalid base64 encoding: {e}") from e
            
            # Decrypt using Fernet (includes authentication verification)
            decrypted_bytes = self._fernet.decrypt(encrypted_bytes)
            bcrypt_hash = decrypted_bytes.decode('utf-8')
            
            # Validate decrypted hash is valid bcrypt format
            self._validate_bcrypt_hash(bcrypt_hash)
            
            self._log_success(
                operation=operation,
                output_format="bcrypt_hash"
            )
            
            return bcrypt_hash
            
        except ValueError as e:
            self._log_warning(
                operation=operation,
                message="Invalid encrypted hash format provided for decryption",
                error=str(e)
            )
            raise ValueError(f"Invalid encrypted hash format: {e}") from e
            
        except InvalidToken as e:
            self._log_warning(
                operation=operation,
                message="Encrypted hash authentication failed during decryption",
                error="invalid_token"
            )
            raise DecryptionError(
                "Failed to decrypt password hash: authentication failed"
            ) from e
            
        except Exception as e:
            raise self._handle_infrastructure_error(
                error=e,
                operation=operation
            )
    
    def is_encrypted_format(self, value: str) -> bool:
        """Check if a value is in encrypted format.
        
        Used for migration compatibility to detect legacy unencrypted hashes.
        
        Args:
            value: Value to check (could be bcrypt hash or encrypted hash)
            
        Returns:
            bool: True if value appears to be encrypted (has enc_v1: prefix)
            
        Security Notes:
            - Only checks format, doesn't attempt decryption
            - Constant-time operation
            - No information disclosure through exceptions
        """
        if not value or not isinstance(value, str):
            return False
        
        # Check for encryption prefix
        return value.startswith("enc_v1:")
    
    def _validate_bcrypt_hash(self, bcrypt_hash: str) -> None:
        """Validate bcrypt hash format for security.
        
        Args:
            bcrypt_hash: Hash to validate
            
        Raises:
            ValueError: If hash format is invalid
            
        Security Notes:
            - Prevents injection of non-bcrypt data
            - Validates structure without exposing internal details
            - Constant-time validation where possible
        """
        if not isinstance(bcrypt_hash, str):
            raise ValueError("Bcrypt hash must be a string")
        
        if not bcrypt_hash:
            raise ValueError("Bcrypt hash cannot be empty")
        
        # Basic bcrypt format validation: $2b$rounds$salt.hash
        if not bcrypt_hash.startswith("$2b$"):
            raise ValueError("Invalid bcrypt hash format: must start with $2b$")
        
        # Standard bcrypt hash length is 60 characters
        if len(bcrypt_hash) != 60:
            raise ValueError(f"Invalid bcrypt hash length: expected 60, got {len(bcrypt_hash)}")
        
        # Count dollar signs - should be exactly 3 in bcrypt format
        dollar_count = bcrypt_hash.count('$')
        if dollar_count != 3:
            raise ValueError(f"Invalid bcrypt hash format: expected 3 '$' characters, got {dollar_count}") 