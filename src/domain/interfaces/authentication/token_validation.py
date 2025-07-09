"""
Interface for Enhanced Token Validation Service.

This module defines the contract for advanced token validation functionality
with comprehensive security checks and threat detection capabilities.

Follows Interface Segregation Principle by providing focused, client-specific interfaces.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class IEnhancedTokenValidationService(ABC):
    """
    Interface for enhanced token validation with advanced security features.
    
    This interface defines the contract for validating token pairs with
    comprehensive security checks including JTI matching, cross-user attack
    prevention, and session consistency validation.
    """
    
    @abstractmethod
    async def validate_token_pair(
        self,
        access_token: str,
        refresh_token: str,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None,
        language: str = "en",
    ) -> Dict[str, Any]:
        """
        Validate access and refresh token pair with comprehensive security checks.
        
        This method implements the core security requirement that both tokens
        must belong to the same session (same JTI) with additional threat detection.
        
        Args:
            access_token: Raw access token string
            refresh_token: Raw refresh token string
            client_ip: Client IP address for security logging
            user_agent: Client user agent for analysis
            correlation_id: Request correlation ID for tracing
            language: Language for error messages
            
        Returns:
            Dict containing validated user and token payloads with metadata:
            {
                "user": User,
                "access_payload": Dict[str, Any],
                "refresh_payload": Dict[str, Any],
                "validation_metadata": Dict[str, Any]
            }
            
        Raises:
            AuthenticationError: If validation fails or security violation detected
        """
        pass
    
    @abstractmethod
    def get_validation_metrics(self) -> Dict[str, Any]:
        """
        Get validation performance and security metrics.
        
        Returns:
            Dict containing validation metrics and statistics
        """
        pass 