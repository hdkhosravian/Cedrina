"""Authentication Context and Metrics for Unified Authentication Service.

This module contains value objects for authentication context and metrics
that are used across the unified authentication service components.
"""

import time
from typing import Dict, Any
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AuthenticationContext:
    """Context object for authentication operations with security metadata.
    
    This value object encapsulates all security-related context for
    authentication operations, ensuring consistent security handling
    across different authentication methods.
    
    Attributes:
        client_ip: Client IP address for security context
        user_agent: User agent string for security context  
        correlation_id: Request correlation ID for tracking
        language: Language code for I18N error messages
        security_metadata: Additional security metadata
    """
    
    client_ip: str
    user_agent: str
    correlation_id: str
    language: str = "en"
    security_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AuthenticationMetrics:
    """Authentication metrics for monitoring and performance analysis.
    
    This value object encapsulates authentication performance metrics
    for real-time monitoring and capacity planning.
    
    Attributes:
        total_authentications: Total authentication attempts
        successful_authentications: Successful authentication attempts
        failed_authentications: Failed authentication attempts
        oauth_authentications: OAuth authentication attempts
        security_incidents: Security incident count
        average_auth_time_ms: Average authentication time in milliseconds
    """
    
    total_authentications: int = 0
    successful_authentications: int = 0
    failed_authentications: int = 0
    oauth_authentications: int = 0
    security_incidents: int = 0
    average_auth_time_ms: float = 0.0
    
    def update_success(self, duration_ms: float, oauth: bool = False) -> 'AuthenticationMetrics':
        """Update metrics for successful authentication.
        
        Args:
            duration_ms: Authentication duration in milliseconds
            oauth: Whether this was an OAuth authentication
            
        Returns:
            AuthenticationMetrics: Updated metrics
        """
        new_total = self.total_authentications + 1
        new_successful = self.successful_authentications + 1
        new_oauth = self.oauth_authentications + (1 if oauth else 0)
        
        # Calculate new average time
        new_avg = ((self.average_auth_time_ms * self.total_authentications) + duration_ms) / new_total
        
        return AuthenticationMetrics(
            total_authentications=new_total,
            successful_authentications=new_successful,
            failed_authentications=self.failed_authentications,
            oauth_authentications=new_oauth,
            security_incidents=self.security_incidents,
            average_auth_time_ms=new_avg
        )
    
    def update_failure(self, duration_ms: float, oauth: bool = False) -> 'AuthenticationMetrics':
        """Update metrics for failed authentication.
        
        Args:
            duration_ms: Authentication duration in milliseconds
            oauth: Whether this was an OAuth authentication
            
        Returns:
            AuthenticationMetrics: Updated metrics
        """
        new_total = self.total_authentications + 1
        new_failed = self.failed_authentications + 1
        new_oauth = self.oauth_authentications + (1 if oauth else 0)
        
        # Calculate new average time
        new_avg = ((self.average_auth_time_ms * self.total_authentications) + duration_ms) / new_total
        
        return AuthenticationMetrics(
            total_authentications=new_total,
            successful_authentications=self.successful_authentications,
            failed_authentications=new_failed,
            oauth_authentications=new_oauth,
            security_incidents=self.security_incidents,
            average_auth_time_ms=new_avg
        ) 