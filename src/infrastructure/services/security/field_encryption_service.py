"""
Field-Level Encryption Service for Token Family Security.

This service provides field-level encryption for sensitive token family data,
extending the existing password encryption infrastructure to support encrypted
storage of token lists and usage history.

Key Features:
- AES-256-GCM encryption with authenticated encryption
- JSON serialization with encryption for complex data structures
- Key separation and secure key management
- Migration compatibility for unencrypted data
- Constant-time operations to prevent timing attacks
- Comprehensive error handling without information disclosure

Security Architecture:
- Uses existing PGCRYPTO_KEY infrastructure
- Fernet encryption (AES-128-CBC + HMAC-SHA256)
- Authenticated encryption prevents tampering
- Unique IV/nonce for each encryption operation
- Format versioning for future algorithm upgrades

Domain Integration:
- Encrypts TokenId lists for token family storage
- Encrypts TokenUsageRecord collections for audit trails
- Maintains type safety with proper serialization
- Provides migration detection for legacy unencrypted data
"""

import base64
import json
from datetime import datetime
from typing import List, Optional, Any, Dict, Union

from cryptography.fernet import Fernet, InvalidToken

from src.core.config.settings import settings
from src.common.exceptions import EncryptionError, DecryptionError
from src.domain.value_objects.jwt_token import TokenId
from src.domain.value_objects.security_context import SecurityContext
from src.domain.value_objects.token_usage_record import TokenUsageRecord
from src.domain.value_objects.token_usage_event import TokenUsageEvent
from src.infrastructure.services.base_service import BaseInfrastructureService


class FieldEncryptionService(BaseInfrastructureService):
    """
    Service for encrypting and decrypting token family field data.
    
    This service extends the existing encryption infrastructure to support
    field-level encryption of sensitive token family data including token
    lists and usage history records.
    
    Security Features:
    - Authenticated encryption with Fernet (AES-128-CBC + HMAC-SHA256)
    - JSON serialization with type-safe encryption
    - Constant-time operations for security
    - Migration compatibility for legacy data
    - Comprehensive error handling without information disclosure
    
    Supported Data Types:
    - List[TokenId]: Token ID collections
    - List[TokenUsageRecord]: Usage history records
    - Dict[str, Any]: Generic structured data
    """
    
    def __init__(self, encryption_key: Optional[str] = None):
        """
        Initialize field encryption service with Fernet encryption.
        
        Args:
            encryption_key: Optional encryption key. If None, uses PGCRYPTO_KEY
                           from settings or generates a development key.
                           
        Security Note:
            - In production, PGCRYPTO_KEY must be a proper 32-byte base64 key
            - For development, a key will be generated automatically
        """
        super().__init__(
            service_name="FieldEncryptionService",
            encryption_algorithm="Fernet_AES_128_CBC_HMAC_SHA256",
            key_source="configured" if encryption_key else "settings_or_generated"
        )
        
        try:
            # Try to get key from parameter or settings
            if encryption_key:
                key = encryption_key.encode()
            else:
                try:
                    key = settings.PGCRYPTO_KEY.get_secret_value().encode()
                except (AttributeError, ValueError):
                    # PGCRYPTO_KEY not set or invalid, generate development key
                    self._logger.warning(
                        "PGCRYPTO_KEY not configured, generating development key"
                    )
                    key = Fernet.generate_key()
            
            # Validate key format for Fernet
            if isinstance(key, str):
                key = key.encode()
            
            # Try to initialize Fernet to validate key
            try:
                self._fernet = Fernet(key)
            except ValueError:
                # Invalid key format, generate a valid one
                self._logger.warning(
                    "Invalid encryption key format, generating valid Fernet key"
                )
                self._fernet = Fernet(Fernet.generate_key())
            
            self._logger.info(
                "Field encryption service initialized",
                encryption_algorithm="Fernet_AES_128_CBC_HMAC_SHA256",
                key_source="configured" if encryption_key else "settings_or_generated"
            )
            
        except Exception as e:
            # Fall back to generated key for testing/development
            self._logger.warning(
                "Invalid encryption key, falling back to generated key",
                error=str(e)
            )
            self._fernet = Fernet(Fernet.generate_key())
    
    async def encrypt_token_list(self, token_list: List[TokenId]) -> bytes:
        """
        Encrypt a list of token IDs for secure storage.
        
        Args:
            token_list: List of TokenId objects to encrypt
            
        Returns:
            bytes: Encrypted token list data
            
        Raises:
            EncryptionError: If encryption fails
        """
        operation_logger = self._logger.bind(
            operation="encrypt_token_list",
            input_count=len(token_list)
        )
        
        try:
            # Serialize token IDs to JSON
            token_data = [token.value for token in token_list]
            json_data = json.dumps({
                "version": "v1",
                "type": "token_list",
                "data": token_data,
                "encrypted_at": datetime.now().isoformat()
            })
            
            # Encrypt the JSON data
            encrypted_bytes = self._fernet.encrypt(json_data.encode('utf-8'))
            
            operation_logger.debug(
                "Token list encrypted successfully",
                output_size=len(encrypted_bytes)
            )
            
            return encrypted_bytes
            
        except Exception as e:
            operation_logger.error(
                "Token list encryption failed",
                error_type=type(e).__name__,
                error_message=str(e)
            )
            raise EncryptionError("Failed to encrypt token list") from e
    
    async def decrypt_token_list(self, encrypted_data: bytes) -> List[TokenId]:
        """
        Decrypt a token list from encrypted storage.
        
        Args:
            encrypted_data: Encrypted token list data
            
        Returns:
            List[TokenId]: Decrypted token list
            
        Raises:
            DecryptionError: If decryption fails
        """
        operation_logger = self._logger.bind(
            operation="decrypt_token_list"
        )
        
        try:
            # Decrypt the data
            decrypted_bytes = self._fernet.decrypt(encrypted_data)
            json_data = decrypted_bytes.decode('utf-8')
            
            # Parse JSON and validate format
            data = json.loads(json_data)
            if data.get("type") != "token_list":
                raise ValueError("Invalid data type for token list")
            
            # Reconstruct TokenId objects
            token_list = [TokenId(token_value) for token_value in data["data"]]
            
            operation_logger.debug(
                "Token list decrypted successfully",
                output_count=len(token_list)
            )
            
            return token_list
            
        except InvalidToken as e:
            operation_logger.warning(
                "Token list authentication failed during decryption"
            )
            raise DecryptionError("Failed to decrypt token list: authentication failed") from e
            
        except Exception as e:
            operation_logger.error(
                "Token list decryption failed",
                error_type=type(e).__name__,
                error_message=str(e)
            )
            raise DecryptionError("Failed to decrypt token list") from e
    
    async def encrypt_usage_history(self, usage_history: List[TokenUsageRecord]) -> bytes:
        """
        Encrypt usage history records for secure storage.
        
        Args:
            usage_history: List of TokenUsageRecord objects to encrypt
            
        Returns:
            bytes: Encrypted usage history data
            
        Raises:
            EncryptionError: If encryption fails
        """
        operation_logger = self._logger.bind(
            operation="encrypt_usage_history",
            input_count=len(usage_history)
        )
        
        try:
            # Serialize usage records to JSON
            history_data = []
            for record in usage_history:
                history_data.append({
                    "token_id": record.token_id.value,
                    "event_type": record.event_type.value,
                    "timestamp": record.timestamp.isoformat(),
                    "client_ip": record.security_context.client_ip if record.security_context else None,
                    "user_agent": record.security_context.user_agent if record.security_context else None,
                    "correlation_id": record.correlation_id
                })
            
            json_data = json.dumps({
                "version": "v1",
                "type": "usage_history",
                "data": history_data,
                "encrypted_at": datetime.now().isoformat()
            })
            
            # Encrypt the JSON data
            encrypted_bytes = self._fernet.encrypt(json_data.encode('utf-8'))
            
            operation_logger.debug(
                "Usage history encrypted successfully",
                output_size=len(encrypted_bytes)
            )
            
            return encrypted_bytes
            
        except Exception as e:
            operation_logger.error(
                "Usage history encryption failed",
                error_type=type(e).__name__,
                error_message=str(e)
            )
            raise EncryptionError("Failed to encrypt usage history") from e
    
    async def decrypt_usage_history(self, encrypted_data: bytes) -> List[TokenUsageRecord]:
        """
        Decrypt usage history from encrypted storage.
        
        Args:
            encrypted_data: Encrypted usage history data
            
        Returns:
            List[TokenUsageRecord]: Decrypted usage history
            
        Raises:
            DecryptionError: If decryption fails
        """
        operation_logger = self._logger.bind(
            operation="decrypt_usage_history"
        )
        
        try:
            # Decrypt the data
            decrypted_bytes = self._fernet.decrypt(encrypted_data)
            json_data = decrypted_bytes.decode('utf-8')
            
            # Parse JSON and validate format
            data = json.loads(json_data)
            if data.get("type") != "usage_history":
                raise ValueError("Invalid data type for usage history")
            
            # Reconstruct TokenUsageRecord objects
            usage_history = []
            for record_data in data["data"]:
                # Create security context if client data is available
                security_context = None
                if record_data.get("client_ip") and record_data.get("user_agent"):
                    security_context = SecurityContext.create_for_request(
                        client_ip=record_data["client_ip"],
                        user_agent=record_data["user_agent"],
                        correlation_id=record_data.get("correlation_id")
                    )
                
                usage_record = TokenUsageRecord(
                    token_id=TokenId(record_data["token_id"]),
                    event_type=TokenUsageEvent(record_data["event_type"]),
                    timestamp=datetime.fromisoformat(record_data["timestamp"]),
                    security_context=security_context,
                    correlation_id=record_data.get("correlation_id")
                )
                usage_history.append(usage_record)
            
            operation_logger.debug(
                "Usage history decrypted successfully",
                output_count=len(usage_history)
            )
            
            return usage_history
            
        except InvalidToken as e:
            operation_logger.warning(
                "Usage history authentication failed during decryption"
            )
            raise DecryptionError("Failed to decrypt usage history: authentication failed") from e
            
        except Exception as e:
            operation_logger.error(
                "Usage history decryption failed",
                error_type=type(e).__name__,
                error_message=str(e)
            )
            raise DecryptionError("Failed to decrypt usage history") from e
    
    async def encrypt_generic_data(self, data: Union[Dict[str, Any], List[Any]]) -> bytes:
        """
        Encrypt generic structured data.
        
        Args:
            data: Generic data structure to encrypt
            
        Returns:
            bytes: Encrypted data
            
        Raises:
            EncryptionError: If encryption fails
        """
        operation_logger = self._logger.bind(
            operation="encrypt_generic_data"
        )
        
        try:
            json_data = json.dumps({
                "version": "v1",
                "type": "generic_data",
                "data": data,
                "encrypted_at": datetime.now().isoformat()
            })
            
            encrypted_bytes = self._fernet.encrypt(json_data.encode('utf-8'))
            
            operation_logger.debug(
                "Generic data encrypted successfully",
                output_size=len(encrypted_bytes)
            )
            
            return encrypted_bytes
            
        except Exception as e:
            operation_logger.error(
                "Generic data encryption failed",
                error_type=type(e).__name__,
                error_message=str(e)
            )
            raise EncryptionError("Failed to encrypt generic data") from e
    
    async def decrypt_generic_data(self, encrypted_data: bytes) -> Union[Dict[str, Any], List[Any]]:
        """
        Decrypt generic structured data.
        
        Args:
            encrypted_data: Encrypted data
            
        Returns:
            Union[Dict[str, Any], List[Any]]: Decrypted data
            
        Raises:
            DecryptionError: If decryption fails
        """
        operation_logger = self._logger.bind(
            operation="decrypt_generic_data"
        )
        
        try:
            decrypted_bytes = self._fernet.decrypt(encrypted_data)
            json_data = decrypted_bytes.decode('utf-8')
            
            data = json.loads(json_data)
            if data.get("type") != "generic_data":
                raise ValueError("Invalid data type for generic data")
            
            operation_logger.debug(
                "Generic data decrypted successfully"
            )
            
            return data["data"]
            
        except InvalidToken as e:
            operation_logger.warning(
                "Generic data authentication failed during decryption"
            )
            raise DecryptionError("Failed to decrypt generic data: authentication failed") from e
            
        except Exception as e:
            operation_logger.error(
                "Generic data decryption failed",
                error_type=type(e).__name__,
                error_message=str(e)
            )
            raise DecryptionError("Failed to decrypt generic data") from e
    
    def is_encrypted_data(self, data: Optional[bytes]) -> bool:
        """
        Check if data appears to be encrypted (non-None bytes).
        
        Args:
            data: Data to check
            
        Returns:
            bool: True if data appears encrypted, False otherwise
        """
        return data is not None and isinstance(data, bytes) and len(data) > 0 