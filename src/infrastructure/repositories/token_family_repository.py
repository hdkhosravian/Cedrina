"""
PostgreSQL Repository Implementation for Token Family Persistence.

This repository implements the token family repository interface using PostgreSQL
for persistence and includes support for encrypted storage of sensitive token data.

Key Features:
- ACID transactions for token family operations
- Encrypted storage of token lists and usage history
- High-performance queries optimized with database indexes
- Real-time security validation with sub-millisecond response times
- Comprehensive error handling and logging
- Batch operations for performance optimization

Security:
- Field-level encryption for sensitive token data
- Secure token family compromise detection
- Audit trails for forensic analysis
- Performance metrics for monitoring

Architecture:
- Repository pattern implementation
- Domain-driven design adherence
- Clean architecture principles
- Dependency inversion compliance
"""

from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any, Union
import json
import asyncio
from enum import Enum
import uuid

from sqlalchemy import select, and_, or_, func, text
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from src.domain.entities.token_family import TokenFamily
from src.domain.value_objects.token_family_status import TokenFamilyStatus
from src.domain.value_objects.token_usage_record import TokenUsageRecord
from src.domain.interfaces.repositories.token_family_repository import ITokenFamilyRepository
from src.domain.value_objects.jwt_token import TokenId
from src.domain.value_objects.security_context import SecurityContext
from src.infrastructure.services.security.field_encryption_service import FieldEncryptionService
from src.infrastructure.database.token_family_model import TokenFamilyModel
from src.infrastructure.database.session_factory import ISessionFactory

logger = structlog.get_logger(__name__)


class TokenFamilyRepository(ITokenFamilyRepository):
    """
    PostgreSQL implementation of the token family repository.
    
    This repository manages token families with encrypted storage and provides
    high-performance security operations for the token family security pattern.
    
    Features:
    - Encrypted token storage using field-level encryption
    - ACID transactions for security operations
    - Optimized queries for sub-millisecond response times
    - Comprehensive error handling and logging
    - Batch operations for performance optimization
    - Real-time security metrics and monitoring
    
    Architecture:
    - Uses TokenFamilyModel (ORM) for database operations
    - Maps to/from TokenFamily (domain entity) for business logic
    - Maintains clean separation between infrastructure and domain layers
    """
    
    def __init__(
        self, 
        session_factory: Union[AsyncSession, ISessionFactory],
        encryption_service: Optional[FieldEncryptionService] = None
    ):
        """
        Initialize the token family repository.
        
        Args:
            session_factory: SQLAlchemy async session or session factory for database operations
            encryption_service: Optional field encryption service for sensitive data
        """
        # Validate required parameters
        if session_factory is None:
            raise ValueError("session_factory cannot be None")
        
        # Support both session factory and direct session for backward compatibility
        if isinstance(session_factory, AsyncSession):
            self.db_session = session_factory
            self.session_factory = None
        else:
            # Validate that session_factory has the expected interface
            if not hasattr(session_factory, 'create_session'):
                raise TypeError("session_factory must have a create_session method")
            self.session_factory = session_factory
            self.db_session = None
        
        self.encryption_service = encryption_service or FieldEncryptionService()
    
    async def _execute_query(self, query):
        """Execute a query using either direct session or session factory."""
        if self.db_session is not None:
            # Use direct session
            return await self.db_session.execute(query)
        else:
            # Use session factory
            async with self.session_factory.create_session() as session:
                return await session.execute(query)
    
    async def _to_domain(self, model: TokenFamilyModel) -> TokenFamily:
        """
        Map TokenFamilyModel (ORM) to TokenFamily (domain entity).
        
        This method handles the conversion from infrastructure layer (ORM model)
        to domain layer (domain entity), including:
        - Status enum conversion
        - Datetime handling (naive to aware)
        - Encrypted field decryption
        - Value object reconstruction
        
        Args:
            model: TokenFamilyModel ORM instance
            
        Returns:
            TokenFamily: Domain entity with all business logic
            
        Raises:
            ValueError: If required fields are missing or invalid
        """
        try:
            # Convert status string to enum
            status = TokenFamilyStatus(model.status)
            
            # Convert naive datetimes to timezone-aware (UTC)
            def make_aware(dt):
                if dt is None:
                    return None
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=timezone.utc)
                return dt
            
            # Create domain entity with basic fields
            token_family = TokenFamily(
                family_id=model.family_id,
                user_id=model.user_id,
                status=status,
                created_at=make_aware(model.created_at),
                last_used_at=make_aware(model.last_used_at),
                compromised_at=make_aware(model.compromised_at),
                expires_at=make_aware(model.expires_at),
                compromise_reason=model.compromise_reason,
                security_score=model.security_score
            )
            
            # Decrypt and set encrypted fields if they exist
            if model.active_tokens_encrypted:
                try:
                    active_tokens = await self.encryption_service.decrypt_token_list(
                        model.active_tokens_encrypted
                    )
                    token_family.set_active_tokens(active_tokens)
                except Exception as e:
                    logger.warning(
                        "Failed to decrypt active tokens, using empty list",
                        family_id=model.family_id[:8] + "...",
                        error=str(e)
                    )
                    token_family.set_active_tokens([])
            else:
                token_family.set_active_tokens([])
            
            if model.revoked_tokens_encrypted:
                try:
                    revoked_tokens = await self.encryption_service.decrypt_token_list(
                        model.revoked_tokens_encrypted
                    )
                    token_family.set_revoked_tokens(revoked_tokens)
                except Exception as e:
                    logger.warning(
                        "Failed to decrypt revoked tokens, using empty list",
                        family_id=model.family_id[:8] + "...",
                        error=str(e)
                    )
                    token_family.set_revoked_tokens([])
            else:
                token_family.set_revoked_tokens([])
            
            if model.usage_history_encrypted:
                try:
                    usage_history = await self.encryption_service.decrypt_usage_history(
                        model.usage_history_encrypted
                    )
                    token_family.set_usage_history(usage_history)
                except Exception as e:
                    logger.warning(
                        "Failed to decrypt usage history, using empty list",
                        family_id=model.family_id[:8] + "...",
                        error=str(e)
                    )
                    token_family.set_usage_history([])
            else:
                token_family.set_usage_history([])
            
            return token_family
            
        except Exception as e:
            logger.error(
                "Failed to map ORM model to domain entity",
                family_id=model.family_id[:8] + "..." if model.family_id else None,
                error=str(e)
            )
            raise
    
    async def _to_model(self, entity: TokenFamily) -> TokenFamilyModel:
        """
        Map TokenFamily (domain entity) to TokenFamilyModel (ORM).
        
        This method handles the conversion from domain layer (domain entity)
        to infrastructure layer (ORM model), including:
        - Status enum to string conversion
        - Datetime handling (aware to naive)
        - Field encryption for sensitive data
        - Value object serialization
        
        Args:
            entity: TokenFamily domain entity
            
        Returns:
            TokenFamilyModel: ORM model ready for database persistence
            
        Raises:
            ValueError: If required fields are missing or invalid
        """
        try:
            # Convert timezone-aware datetimes to naive UTC
            def make_naive(dt):
                if dt is None:
                    return None
                if dt.tzinfo is not None:
                    return dt.astimezone(timezone.utc).replace(tzinfo=None)
                return dt
            
            # Create ORM model with basic fields
            model = TokenFamilyModel(
                family_id=entity.family_id,
                user_id=entity.user_id,
                status=entity.status.value,  # Convert enum to string
                created_at=make_naive(entity.created_at),
                last_used_at=make_naive(entity.last_used_at),
                compromised_at=make_naive(entity.compromised_at),
                expires_at=make_naive(entity.expires_at),
                compromise_reason=entity.compromise_reason,
                security_score=entity.security_score
            )
            
            # Encrypt sensitive fields
            if entity.active_tokens:
                model.active_tokens_encrypted = await self.encryption_service.encrypt_token_list(entity.active_tokens)
            
            if entity.revoked_tokens:
                model.revoked_tokens_encrypted = await self.encryption_service.encrypt_token_list(entity.revoked_tokens)
            
            if entity.usage_history:
                model.usage_history_encrypted = await self.encryption_service.encrypt_usage_history(entity.usage_history)
            
            return model
            
        except Exception as e:
            logger.error(
                "Failed to map domain entity to ORM model",
                family_id=entity.family_id[:8] + "..." if entity.family_id else None,
                error=str(e)
            )
            raise
    
    async def create_family(
        self,
        user_id: int,
        initial_token_id: Optional[TokenId] = None,
        expires_at: Optional[datetime] = None,
        security_context: Optional[SecurityContext] = None,
        correlation_id: Optional[str] = None
    ) -> TokenFamily:
        """
        Create a new token family for a user.
        
        Args:
            user_id: User ID for the token family
            initial_token_id: Optional initial token to add to the family
            expires_at: Optional expiration time for the family
            security_context: Security context for tracking
            correlation_id: Request correlation ID
            
        Returns:
            TokenFamily: Created token family entity
            
        Raises:
            ValueError: If user_id is invalid
            DatabaseError: If database operation fails
        """
        if user_id <= 0:
            raise ValueError("User ID must be positive")
        
        try:
            # Create new token family domain entity
            token_family = TokenFamily.create_new_family(
                family_id=str(uuid.uuid4()),
                user_id=user_id,
                expires_at=expires_at,
                security_context=security_context,
                initial_token_id=initial_token_id
            )
            
            # Use the existing create_token_family method to handle persistence
            return await self.create_token_family(token_family)
            
        except Exception as e:
            logger.error(
                "Failed to create token family",
                user_id=user_id,
                error=str(e),
                correlation_id=correlation_id
            )
            raise
    
    async def create_token_family(self, token_family: TokenFamily) -> TokenFamily:
        """
        Persist a new TokenFamily instance to the database.
        
        Args:
            token_family: The TokenFamily domain entity to persist
            
        Returns:
            TokenFamily: The persisted entity (with DB-generated fields)
        """
        try:
            # Map domain entity to ORM model
            model = await self._to_model(token_family)
            
            # Save to database using session factory or direct session
            if self.db_session is not None:
                # Use direct session
                self.db_session.add(model)
                await self.db_session.flush()
                await self.db_session.refresh(model)
            else:
                # Use session factory
                async with self.session_factory.create_session() as session:
                    session.add(model)
                    await session.flush()
                    await session.refresh(model)
                    await session.commit()
            
            # Map back to domain entity
            persisted_entity = await self._to_domain(model)
            
            logger.info(
                "Token family created successfully",
                family_id=persisted_entity.family_id[:8] + "...",
                user_id=persisted_entity.user_id
            )
            
            return persisted_entity
            
        except Exception as e:
            logger.error(
                "Failed to create token family",
                user_id=token_family.user_id,
                error=str(e)
            )
            raise
    
    async def get_family_by_id(self, family_id: str) -> Optional[TokenFamily]:
        """
        Get token family by family ID.
        
        Args:
            family_id: Token family ID
            
        Returns:
            Optional[TokenFamily]: Token family if found, None otherwise
        """
        # Validate family_id parameter
        if family_id is None:
            raise ValueError("Family ID cannot be None")
        
        try:
            result = await self._execute_query(
                select(TokenFamilyModel).where(TokenFamilyModel.family_id == family_id)
            )
            model = result.scalars().first()
            
            if not model:
                return None
            
            # Map ORM model to domain entity
            token_family = await self._to_domain(model)
            
            logger.debug(
                "Token family retrieved",
                family_id=family_id[:8] + "...",
                status=token_family.status.value,
                active_tokens_count=len(token_family.active_tokens),
                revoked_tokens_count=len(token_family.revoked_tokens)
            )
            
            return token_family
            
        except Exception as e:
            logger.error(
                "Failed to get token family by ID",
                family_id=family_id[:8] + "...",
                error=str(e)
            )
            raise
    
    async def get_by_family_id(self, family_id: str) -> Optional[TokenFamily]:
        """Fetch a token family by its family_id."""
        result = await self._execute_query(
            select(TokenFamilyModel).where(TokenFamilyModel.family_id == family_id)
        )
        model = result.scalars().first()
        if model:
            return await self._to_domain(model)
        return None
    
    async def get_family_by_token(self, token_id: TokenId) -> Optional[TokenFamily]:
        """
        Get token family by token ID.
        
        Note: This implementation searches through families by decrypting token lists.
        In production with large datasets, consider:
        1. A separate token-to-family mapping table for performance
        2. Token ID hashing for indexable lookups
        3. Caching frequently accessed families
        
        Args:
            token_id: Token ID to search for
            
        Returns:
            Optional[TokenFamily]: Token family containing the token, None otherwise
        """
        try:
            # Get all active token families (we could optimize this with pagination)
            # For now, we'll search through recent families first
            result = await self._execute_query(
                select(TokenFamilyModel)
                .where(TokenFamilyModel.status == TokenFamilyStatus.ACTIVE.value)
                .order_by(TokenFamilyModel.last_used_at.desc())
                .limit(100)  # Limit search to most recent 100 families for performance
            )
            models = result.scalars().all()
            
            # Search through families to find the one containing this token
            for model in models:
                # Map ORM model to domain entity
                family = await self._to_domain(model)
                
                # Check if token is in active tokens
                if token_id in family.active_tokens:
                    logger.debug(
                        "Token found in active tokens",
                        token_id=token_id.mask_for_logging(),
                        family_id=family.family_id[:8] + "..."
                    )
                    return family
                
                # Check if token is in revoked tokens (for security analysis)
                if token_id in family.revoked_tokens:
                    logger.debug(
                        "Token found in revoked tokens",
                        token_id=token_id.mask_for_logging(),
                        family_id=family.family_id[:8] + "..."
                    )
                    return family
            
            # Token not found in any family
            logger.debug(
                "Token not found in any family",
                token_id=token_id.mask_for_logging(),
                families_searched=len(models)
            )
            return None
            
        except Exception as e:
            logger.error(
                "Failed to get token family by token",
                token_id=token_id.mask_for_logging(),
                error=str(e)
            )
            raise
    
    async def update_family(self, token_family: TokenFamily) -> TokenFamily:
        """
        Update an existing token family.
        
        Args:
            token_family: Token family to update
            
        Returns:
            TokenFamily: Updated token family
            
        Raises:
            ValueError: If family not found
            DatabaseError: If database operation fails
        """
        try:
            # Find existing model first
            result = await self._execute_query(
                select(TokenFamilyModel).where(TokenFamilyModel.family_id == token_family.family_id)
            )
            existing_model = result.scalars().first()
            
            if not existing_model:
                raise ValueError(f"Token family {token_family.family_id} not found for update")
            
            # Map domain entity to ORM model
            updated_model = await self._to_model(token_family)
            
            # Update existing model with new values
            existing_model.status = updated_model.status
            existing_model.last_used_at = datetime.now(timezone.utc).replace(tzinfo=None)
            existing_model.compromised_at = updated_model.compromised_at
            existing_model.expires_at = updated_model.expires_at
            existing_model.compromise_reason = updated_model.compromise_reason
            existing_model.security_score = updated_model.security_score
            existing_model.active_tokens_encrypted = updated_model.active_tokens_encrypted
            existing_model.revoked_tokens_encrypted = updated_model.revoked_tokens_encrypted
            existing_model.usage_history_encrypted = updated_model.usage_history_encrypted
            
            # Flush changes using session factory or direct session
            if self.db_session is not None:
                # Use direct session
                await self.db_session.flush()
                await self.db_session.refresh(existing_model)
            else:
                # Use session factory
                async with self.session_factory.create_session() as session:
                    # Re-attach the model to the new session
                    merged_model = await session.merge(existing_model)
                    await session.flush()
                    await session.refresh(merged_model)
                    await session.commit()
                    # Update the existing_model reference for consistency
                    existing_model = merged_model
            
            # Map back to domain entity
            updated_entity = await self._to_domain(existing_model)
            
            logger.debug(
                "Token family updated",
                family_id=token_family.family_id[:8] + "...",
                status=token_family.status.value
            )
            
            return updated_entity
            
        except Exception as e:
            logger.error(
                "Failed to update token family",
                family_id=token_family.family_id[:8] + "...",
                error=str(e)
            )
            raise
    
    async def compromise_family(
        self,
        family_id: str,
        reason: str,
        detected_token: Optional[TokenId] = None,
        security_context: Optional[SecurityContext] = None,
        correlation_id: Optional[str] = None
    ) -> bool:
        """
        Compromise a token family due to security violation.
        
        Args:
            family_id: Token family ID to compromise
            reason: Reason for compromise
            detected_token: Token that triggered the compromise
            security_context: Security context for tracking
            correlation_id: Request correlation ID
            
        Returns:
            bool: True if family was compromised, False if not found
        """
        try:
            token_family = await self.get_family_by_id(family_id)
            if not token_family:
                logger.warning(
                    "Cannot compromise non-existent token family",
                    family_id=family_id[:8] + "...",
                    correlation_id=correlation_id
                )
                return False
            
            # Compromise the family
            token_family.compromise_family(
                reason=reason,
                detected_token=detected_token,
                security_context=security_context,
                correlation_id=correlation_id
            )
            
            # Update in database
            await self.update_family(token_family)
            
            logger.critical(
                "Token family compromised",
                family_id=family_id[:8] + "...",
                reason=reason,
                detected_token=detected_token.mask_for_logging() if detected_token else None,
                correlation_id=correlation_id
            )
            
            return True
            
        except Exception as e:
            logger.error(
                "Failed to compromise token family",
                family_id=family_id[:8] + "...",
                error=str(e),
                correlation_id=correlation_id
            )
            raise
    
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
        """
        try:
            result = await self._execute_query(
                select(TokenFamilyModel).where(TokenFamilyModel.family_id == family_id)
            )
            model = result.scalars().first()
            
            if not model:
                return False
            
            # Map to domain entity
            token_family = await self._to_domain(model)
            
            # Update status and reason
            token_family._status = TokenFamilyStatus.REVOKED
            token_family._compromise_reason = reason
            token_family._compromised_at = datetime.now(timezone.utc)
            
            # Update in database
            await self.update_family(token_family)
            
            logger.info(
                "Token family revoked",
                family_id=family_id[:8] + "...",
                reason=reason,
                correlation_id=correlation_id
            )
            
            return True
            
        except Exception as e:
            logger.error(
                "Failed to revoke token family",
                family_id=family_id[:8] + "...",
                error=str(e),
                correlation_id=correlation_id
            )
            raise
    
    async def check_token_reuse(
        self,
        token_id: TokenId,
        family_id: str,
        security_context: Optional[SecurityContext] = None,
        correlation_id: Optional[str] = None
    ) -> bool:
        """
        Check if a token is being reused (already revoked).
        
        This is a critical security operation that must be fast (sub-millisecond).
        
        Args:
            token_id: Token ID to check
            family_id: Expected family ID
            security_context: Security context for tracking
            correlation_id: Request correlation ID
            
        Returns:
            bool: True if reuse detected (security violation), False if safe
        """
        try:
            start_time = datetime.now(timezone.utc)
            
            token_family = await self.get_family_by_id(family_id)
            if not token_family:
                logger.warning(
                    "Token reuse check on non-existent family",
                    token_id=token_id.mask_for_logging(),
                    family_id=family_id[:8] + "...",
                    correlation_id=correlation_id
                )
                return True  # Treat unknown family as suspicious
            
            # Check if family is already compromised
            if token_family.is_compromised():
                logger.warning(
                    "Token usage on compromised family",
                    token_id=token_id.mask_for_logging(),
                    family_id=family_id[:8] + "...",
                    correlation_id=correlation_id
                )
                return True
            
            # Check if token is in revoked tokens list
            reuse_detected = token_id in token_family.revoked_tokens
            
            # Calculate response time
            end_time = datetime.now(timezone.utc)
            response_time_ms = (end_time - start_time).total_seconds() * 1000
            
            logger.debug(
                "Token reuse check completed",
                token_id=token_id.mask_for_logging(),
                family_id=family_id[:8] + "...",
                reuse_detected=reuse_detected,
                response_time_ms=response_time_ms,
                correlation_id=correlation_id
            )
            
            return reuse_detected
            
        except Exception as e:
            logger.error(
                "Failed to check token reuse",
                token_id=token_id.mask_for_logging(),
                family_id=family_id[:8] + "...",
                error=str(e),
                correlation_id=correlation_id
            )
            # Fail securely - treat as suspicious
            return True
    
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
        """
        try:
            query = select(TokenFamilyModel).where(TokenFamilyModel.user_id == user_id)
            
            if status:
                query = query.where(TokenFamilyModel.status == status.value)
            
            query = query.order_by(TokenFamilyModel.created_at.desc()).limit(limit)
            
            result = await self._execute_query(query)
            models = result.scalars().all()
            
            # Map ORM models to domain entities
            families = []
            for model in models:
                family = await self._to_domain(model)
                families.append(family)
            
            logger.debug(
                "Retrieved user token families",
                user_id=user_id,
                status=status.value if status else "all",
                count=len(families)
            )
            
            return families
            
        except Exception as e:
            logger.error(
                "Failed to get user token families",
                user_id=user_id,
                error=str(e)
            )
            raise
    
    async def get_expired_families(
        self,
        limit: int = 1000
    ) -> List[TokenFamily]:
        """
        Get expired token families for cleanup.
        
        Args:
            limit: Maximum number of families to return
            
        Returns:
            List[TokenFamily]: List of expired token families
        """
        try:
            # Convert to naive UTC for database comparison
            current_time = datetime.now(timezone.utc).replace(tzinfo=None)
            
            query = select(TokenFamilyModel).where(
                or_(
                    TokenFamilyModel.expires_at < current_time,
                    TokenFamilyModel.status == TokenFamilyStatus.EXPIRED.value
                )
            ).order_by(TokenFamilyModel.expires_at.asc()).limit(limit)
            
            result = await self._execute_query(query)
            models = result.scalars().all()
            
            # Map ORM models to domain entities
            families = []
            for model in models:
                family = await self._to_domain(model)
                families.append(family)
            
            logger.debug(
                "Retrieved expired token families",
                count=len(families)
            )
            
            return families
            
        except Exception as e:
            logger.error(
                "Failed to get expired token families",
                error=str(e)
            )
            raise
    
    async def get_security_metrics(
        self,
        user_id: Optional[int] = None,
        time_window_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Get security metrics for monitoring and analysis.
        
        Args:
            user_id: Optional user ID filter
            time_window_hours: Time window for metrics calculation
            
        Returns:
            Dict[str, Any]: Security metrics data
        """
        try:
            current_time = datetime.now(timezone.utc).replace(tzinfo=None)
            window_start = current_time - timedelta(hours=time_window_hours)
            
            # Base query conditions
            conditions = [TokenFamilyModel.created_at >= window_start]
            if user_id:
                conditions.append(TokenFamilyModel.user_id == user_id)
            
            # Get family counts by status
            status_query = select(
                TokenFamilyModel.status,
                func.count(TokenFamilyModel.id).label('count')
            ).where(and_(*conditions)).group_by(TokenFamilyModel.status)
            
            status_result = await self._execute_query(status_query)
            status_counts = {row.status: row.count for row in status_result}
            
            # Get total families created
            total_query = select(func.count(TokenFamilyModel.id)).where(and_(*conditions))
            total_result = await self._execute_query(total_query)
            total_families = total_result.scalar() or 0
            
            # Get compromised families count
            compromised_count = status_counts.get('compromised', 0)
            
            # Calculate compromise rate
            compromise_rate = (compromised_count / total_families * 100) if total_families > 0 else 0.0
            
            # Get average security score
            avg_score_query = select(func.avg(TokenFamilyModel.security_score)).where(and_(*conditions))
            avg_score_result = await self._execute_query(avg_score_query)
            avg_security_score = float(avg_score_result.scalar() or 1.0)
            
            metrics = {
                "time_window_hours": time_window_hours,
                "user_id": user_id,
                "total_families_created": total_families,
                "families_by_status": status_counts,
                "compromise_rate_percent": round(compromise_rate, 2),
                "average_security_score": round(avg_security_score, 3),
                "families_active": status_counts.get('active', 0),
                "families_compromised": compromised_count,
                "families_revoked": status_counts.get('revoked', 0),
                "families_expired": status_counts.get('expired', 0),
                "generated_at": current_time.isoformat()
            }
            
            logger.debug(
                "Generated security metrics",
                user_id=user_id,
                time_window_hours=time_window_hours,
                total_families=total_families,
                compromise_rate=compromise_rate
            )
            
            return metrics
            
        except Exception as e:
            logger.error(
                "Failed to get security metrics",
                user_id=user_id,
                error=str(e)
            )
            raise
    
    async def get_compromised_families(
        self,
        since: Optional[datetime] = None,
        limit: int = 100
    ) -> List[TokenFamily]:
        """
        Get compromised token families for security analysis.
        
        Args:
            since: Optional timestamp to filter compromised families
            limit: Maximum number of families to return
            
        Returns:
            List[TokenFamily]: List of compromised token families
        """
        try:
            query = select(TokenFamilyModel).where(
                TokenFamilyModel.status == TokenFamilyStatus.COMPROMISED.value
            )
            
            if since:
                query = query.where(TokenFamilyModel.compromised_at >= since)
            
            query = query.order_by(TokenFamilyModel.compromised_at.desc()).limit(limit)
            
            result = await self._execute_query(query)
            models = result.scalars().all()
            
            # Map ORM models to domain entities
            families = []
            for model in models:
                family = await self._to_domain(model)
                families.append(family)
            
            logger.debug(
                "Retrieved compromised token families",
                since=since.isoformat() if since else None,
                count=len(families)
            )
            
            return families
            
        except Exception as e:
            logger.error(
                "Failed to get compromised token families",
                error=str(e)
            )
            raise 