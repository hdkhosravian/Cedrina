"""
Token Family Repository Interface.

This interface defines the contract for token family persistence operations,
following the repository pattern from domain-driven design.

The repository abstraction allows the domain layer to remain independent
of infrastructure concerns while providing clear contracts for data operations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional, Dict, Any

from src.domain.entities.token_family import TokenFamily, TokenFamilyStatus
from src.domain.value_objects.jwt_token import TokenId


class ITokenFamilyRepository(ABC):
    """
    Abstract interface for token family repository operations.
    
    This interface defines the contract for token family persistence,
    enabling the domain layer to remain independent of infrastructure
    implementation details.
    
    Repository Responsibilities:
    - Token family CRUD operations
    - Encrypted data persistence 
    - Security validation and metrics
    - Performance optimization
    - Transaction management
    """
    
    @abstractmethod
    async def create_family(
        self,
        user_id: int,
        initial_token_id: Optional[TokenId] = None,
        expires_at: Optional[datetime] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> TokenFamily:
        """
        Create a new token family.
        
        Args:
            user_id: User ID for the token family
            initial_token_id: Optional initial token to add
            expires_at: Optional expiration time
            client_ip: Client IP for security tracking
            user_agent: User agent for security tracking
            correlation_id: Request correlation ID
            
        Returns:
            TokenFamily: Created token family
            
        Raises:
            ValueError: If user_id is invalid
            RepositoryError: If creation fails
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_family_by_id(self, family_id: str) -> Optional[TokenFamily]:
        """
        Retrieve a token family by ID.
        
        Args:
            family_id: Token family ID
            
        Returns:
            Optional[TokenFamily]: Token family if found, None otherwise
            
        Raises:
            RepositoryError: If retrieval fails
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_family_by_token(self, token_id: TokenId) -> Optional[TokenFamily]:
        """
        Retrieve a token family by token ID.
        
        Args:
            token_id: Token ID to search for
            
        Returns:
            Optional[TokenFamily]: Token family containing the token
            
        Raises:
            RepositoryError: If search fails
        """
        raise NotImplementedError
    
    @abstractmethod
    async def update_family(self, token_family: TokenFamily) -> TokenFamily:
        """
        Update an existing token family.
        
        Args:
            token_family: Token family to update
            
        Returns:
            TokenFamily: Updated token family
            
        Raises:
            ValueError: If family not found
            RepositoryError: If update fails
        """
        raise NotImplementedError
    
    @abstractmethod
    async def compromise_family(
        self,
        family_id: str,
        reason: str,
        detected_token: Optional[TokenId] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> bool:
        """
        Compromise a token family due to security violation.
        
        Args:
            family_id: Token family ID to compromise
            reason: Reason for compromise
            detected_token: Token that triggered compromise
            client_ip: Client IP for security tracking
            user_agent: User agent for security tracking
            correlation_id: Request correlation ID
            
        Returns:
            bool: True if family was compromised, False if not found
            
        Raises:
            RepositoryError: If operation fails
        """
        raise NotImplementedError
    
    @abstractmethod
    async def revoke_family(
        self,
        family_id: str,
        reason: str = "Manual revocation",
        correlation_id: Optional[str] = None
    ) -> bool:
        """
        Revoke a token family.
        
        Args:
            family_id: Token family ID to revoke
            reason: Reason for revocation
            correlation_id: Request correlation ID
            
        Returns:
            bool: True if family was revoked, False if not found
            
        Raises:
            RepositoryError: If operation fails
        """
        raise NotImplementedError
    
    @abstractmethod
    async def check_token_reuse(
        self,
        token_id: TokenId,
        family_id: str,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> bool:
        """
        Check if a token is being reused (security violation).
        
        Args:
            token_id: Token ID to check
            family_id: Expected family ID
            client_ip: Client IP for security tracking
            user_agent: User agent for security tracking
            correlation_id: Request correlation ID
            
        Returns:
            bool: True if reuse detected, False if safe
            
        Raises:
            RepositoryError: If check fails
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_user_families(
        self,
        user_id: int,
        status: Optional[TokenFamilyStatus] = None,
        limit: int = 100
    ) -> List[TokenFamily]:
        """
        Get token families for a user.
        
        Args:
            user_id: User ID
            status: Optional status filter
            limit: Maximum number of families to return
            
        Returns:
            List[TokenFamily]: List of token families
            
        Raises:
            RepositoryError: If retrieval fails
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_expired_families(self, limit: int = 1000) -> List[TokenFamily]:
        """
        Get expired token families for cleanup.
        
        Args:
            limit: Maximum number of families to return
            
        Returns:
            List[TokenFamily]: List of expired families
            
        Raises:
            RepositoryError: If retrieval fails
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_security_metrics(
        self,
        user_id: Optional[int] = None,
        time_window_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Get security metrics for monitoring.
        
        Args:
            user_id: Optional user ID filter
            time_window_hours: Time window for metrics
            
        Returns:
            Dict[str, Any]: Security metrics data
            
        Raises:
            RepositoryError: If metrics collection fails
        """
        raise NotImplementedError
    
    @abstractmethod
    async def get_compromised_families(
        self,
        since: Optional[datetime] = None,
        limit: int = 100
    ) -> List[TokenFamily]:
        """
        Get compromised token families for analysis.
        
        Args:
            since: Optional timestamp filter
            limit: Maximum number of families to return
            
        Returns:
            List[TokenFamily]: List of compromised families
            
        Raises:
            RepositoryError: If retrieval fails
        """
        raise NotImplementedError 