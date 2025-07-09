"""
Unified Session Service.

This service manages user sessions using database-only storage with token family
integration, following domain-driven design principles and clean architecture.
"""

import asyncio
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any

from sqlalchemy import select, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select
import structlog

from src.core.config.settings import settings
from src.core.exceptions import AuthenticationError, SessionLimitExceededError
from src.domain.entities.session import Session
from src.domain.entities.token_family import TokenFamily, TokenFamilyStatus
from src.domain.interfaces.repositories.token_family_repository import ITokenFamilyRepository
from src.domain.interfaces import IEventPublisher
from src.domain.events.authentication_events import (
    SessionCreatedEvent,
    SessionRevokedEvent,
    SessionExpiredEvent,
    SessionActivityUpdatedEvent
)
from src.utils.i18n import get_translated_message

logger = structlog.get_logger(__name__)


class UnifiedSessionService:
    """
    Unified session service with token family integration.
    
    This service manages user sessions using database-only storage with
    integration to token families for enhanced security and consistency.
    
    Key Features:
    - Database-only storage eliminates Redis complexity
    - Token family integration for security correlation
    - Comprehensive session lifecycle management
    - Activity tracking and inactivity timeout
    - Concurrent session limits with cleanup
    - Audit trail generation for compliance
    """
    
    def __init__(
        self,
        db_session: AsyncSession,
        token_family_repository: ITokenFamilyRepository,
        event_publisher: IEventPublisher
    ):
        self.db_session = db_session
        self._token_family_repository = token_family_repository
        self._event_publisher = event_publisher
        
        logger.info(
            "UnifiedSessionService initialized",
            storage_type="database_only",
            features=["token_family_integration", "activity_tracking", "audit_trail"]
        )
    
    async def create_session(
        self,
        user_id: int,
        jti: str,
        refresh_token_hash: str,
        expires_at: datetime,
        family_id: Optional[str] = None,
        correlation_id: Optional[str] = None
    ) -> Session:
        """
        Create a new session with token family integration.
        
        Args:
            user_id: User ID for the session
            jti: JWT ID for the session
            refresh_token_hash: Hashed refresh token
            expires_at: Session expiration time
            family_id: Optional token family ID for security correlation
            correlation_id: Request correlation ID for tracing
            
        Returns:
            Session: Created session entity
            
        Raises:
            SessionLimitExceededError: If user exceeds maximum concurrent sessions
            AuthenticationError: If session creation fails
        """
        await self._enforce_session_limits(user_id)
        
        current_time = datetime.now(timezone.utc)
        session = Session(
            user_id=user_id,
            jti=jti,
            refresh_token_hash=refresh_token_hash,
            expires_at=expires_at.replace(tzinfo=None),
            last_activity_at=current_time.replace(tzinfo=None),
            family_id=family_id
        )
        
        try:
            async with self.db_session.begin():
                self.db_session.add(session)
                await self.db_session.commit()
                
                # Publish session created event
                event = SessionCreatedEvent.create(
                    user_id=user_id,
                    jti=jti,
                    family_id=family_id,
                    correlation_id=correlation_id
                )
                await self._event_publisher.publish(event)
                
                logger.info(
                    "Session created successfully",
                    user_id=user_id,
                    jti=jti,
                    family_id=family_id,
                    correlation_id=correlation_id
                )
                
                return session
                
        except Exception as e:
            logger.error(
                "Session creation failed",
                user_id=user_id,
                jti=jti,
                error=str(e),
                correlation_id=correlation_id
            )
            raise AuthenticationError(
                get_translated_message("session_creation_failed", "en")
            )
    
    async def update_session_activity(
        self,
        jti: str,
        user_id: int,
        correlation_id: Optional[str] = None
    ) -> bool:
        """
        Update session activity and validate session.
        
        Args:
            jti: JWT ID of the session
            user_id: User ID
            correlation_id: Request correlation ID
            
        Returns:
            bool: True if session is valid and updated, False otherwise
        """
        session = await self.get_session(jti, user_id)
        if not session:
            return False
        
        if session.revoked_at:
            logger.debug("Session revoked", jti=jti, user_id=user_id)
            return False
        
        current_time = datetime.now(timezone.utc)
        current_time_naive = current_time.replace(tzinfo=None)
        
        if session.expires_at.replace(tzinfo=None) < current_time_naive:
            logger.debug("Session expired", jti=jti, user_id=user_id)
            await self._handle_session_expiration(session, correlation_id)
            return False
        
        inactivity_timeout = timedelta(minutes=settings.SESSION_INACTIVITY_TIMEOUT_MINUTES)
        if session.last_activity_at.replace(tzinfo=None) + inactivity_timeout < current_time_naive:
            logger.info(
                "Session expired due to inactivity",
                jti=jti,
                user_id=user_id,
                last_activity=session.last_activity_at.isoformat()
            )
            await self.revoke_session(jti, user_id, "en", correlation_id)
            return False
        
        try:
            async with self.db_session.begin():
                session.last_activity_at = current_time_naive
                self.db_session.add(session)
                await self.db_session.commit()
                
                # Publish activity update event
                event = SessionActivityUpdatedEvent.create(
                    user_id=user_id,
                    jti=jti,
                    family_id=session.family_id,
                    correlation_id=correlation_id
                )
                await self._event_publisher.publish(event)
                
                return True
                
        except Exception as e:
            logger.error(
                "Session activity update failed",
                jti=jti,
                user_id=user_id,
                error=str(e),
                correlation_id=correlation_id
            )
            return False
    
    async def revoke_session(
        self,
        jti: str,
        user_id: int,
        language: str = "en",
        correlation_id: Optional[str] = None,
        reason: str = "Manual revocation"
    ) -> None:
        """
        Revoke a session with token family integration.
        
        Args:
            jti: JWT ID of the session
            user_id: User ID
            language: Language for error messages
            correlation_id: Request correlation ID
            reason: Reason for revocation
        """
        session = await self.get_session(jti, user_id)
        if not session:
            return
        
        try:
            async with self.db_session.begin():
                session.revoked_at = datetime.now(timezone.utc).replace(tzinfo=None)
                session.revoke_reason = reason
                self.db_session.add(session)
                
                # If session has family_id, compromise the family
                if session.family_id:
                    await self._token_family_repository.compromise_family(
                        family_id=session.family_id,
                        reason=f"Session revoked: {reason}",
                        correlation_id=correlation_id
                    )
                
                await self.db_session.commit()
                
                # Publish session revoked event
                event = SessionRevokedEvent.create(
                    user_id=user_id,
                    jti=jti,
                    family_id=session.family_id,
                    reason=reason,
                    correlation_id=correlation_id
                )
                await self._event_publisher.publish(event)
                
                logger.info(
                    "Session revoked successfully",
                    jti=jti,
                    user_id=user_id,
                    family_id=session.family_id,
                    reason=reason,
                    correlation_id=correlation_id
                )
                
        except Exception as e:
            logger.error(
                "Session revocation failed",
                jti=jti,
                user_id=user_id,
                error=str(e),
                correlation_id=correlation_id
            )
            raise AuthenticationError(
                get_translated_message("session_revocation_failed", language)
            )
    
    async def get_session(self, jti: str, user_id: int) -> Optional[Session]:
        """
        Retrieve a session by JTI and user ID.
        
        Args:
            jti: JWT ID of the session
            user_id: User ID
            
        Returns:
            Optional[Session]: Session entity if found, None otherwise
        """
        try:
            result = await self.db_session.execute(
                select(Session).where(
                    and_(
                        Session.jti == jti,
                        Session.user_id == user_id
                    )
                )
            )
            return result.scalar_one_or_none()
        except Exception as e:
            logger.error(
                "Session retrieval failed",
                jti=jti,
                user_id=user_id,
                error=str(e)
            )
            return None
    
    async def is_session_valid(self, jti: str, user_id: int) -> bool:
        """
        Check if a session is valid and not revoked.
        
        Args:
            jti: JWT ID of the session
            user_id: User ID
            
        Returns:
            bool: True if session is valid, False otherwise
        """
        session = await self.get_session(jti, user_id)
        if not session:
            return False
        
        if session.revoked_at:
            return False
        
        current_time = datetime.now(timezone.utc).replace(tzinfo=None)
        if session.expires_at.replace(tzinfo=None) < current_time:
            return False
        
        return True
    
    async def get_user_active_sessions(self, user_id: int) -> List[Session]:
        """
        Get all active sessions for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List[Session]: List of active sessions
        """
        try:
            current_time = datetime.now(timezone.utc).replace(tzinfo=None)
            result = await self.db_session.execute(
                select(Session).where(
                    and_(
                        Session.user_id == user_id,
                        Session.revoked_at.is_(None),
                        Session.expires_at > current_time
                    )
                ).order_by(Session.last_activity_at.desc())
            )
            return result.scalars().all()
        except Exception as e:
            logger.error(
                "Failed to retrieve user active sessions",
                user_id=user_id,
                error=str(e)
            )
            return []
    
    async def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions and return count of cleaned sessions.
        
        Returns:
            int: Number of sessions cleaned up
        """
        try:
            current_time = datetime.now(timezone.utc).replace(tzinfo=None)
            
            # Get expired sessions
            result = await self.db_session.execute(
                select(Session).where(
                    or_(
                        Session.expires_at < current_time,
                        and_(
                            Session.revoked_at.is_(None),
                            Session.last_activity_at < current_time - timedelta(
                                minutes=settings.SESSION_INACTIVITY_TIMEOUT_MINUTES
                            )
                        )
                    )
                )
            )
            expired_sessions = result.scalars().all()
            
            if not expired_sessions:
                return 0
            
            # Revoke expired sessions
            for session in expired_sessions:
                await self._handle_session_expiration(session)
            
            logger.info(
                "Expired sessions cleaned up",
                count=len(expired_sessions)
            )
            
            return len(expired_sessions)
            
        except Exception as e:
            logger.error(
                "Session cleanup failed",
                error=str(e)
            )
            return 0
    
    async def _enforce_session_limits(self, user_id: int) -> None:
        """Enforce concurrent session limits for user."""
        active_count = await self._get_active_session_count(user_id)
        if active_count >= settings.MAX_CONCURRENT_SESSIONS_PER_USER:
            raise SessionLimitExceededError(
                get_translated_message("session_limit_exceeded", "en")
            )
    
    async def _get_active_session_count(self, user_id: int) -> int:
        """Get count of active sessions for user."""
        try:
            current_time = datetime.now(timezone.utc).replace(tzinfo=None)
            result = await self.db_session.execute(
                select(func.count(Session.id)).where(
                    and_(
                        Session.user_id == user_id,
                        Session.revoked_at.is_(None),
                        Session.expires_at > current_time
                    )
                )
            )
            return result.scalar() or 0
        except Exception as e:
            logger.error(
                "Failed to get active session count",
                user_id=user_id,
                error=str(e)
            )
            return 0
    
    async def _handle_session_expiration(
        self,
        session: Session,
        correlation_id: Optional[str] = None
    ) -> None:
        """Handle session expiration with event publishing."""
        try:
            async with self.db_session.begin():
                session.revoked_at = datetime.now(timezone.utc).replace(tzinfo=None)
                session.revoke_reason = "Session expired"
                self.db_session.add(session)
                await self.db_session.commit()
                
                # Publish session expired event
                event = SessionExpiredEvent.create(
                    user_id=session.user_id,
                    jti=session.jti,
                    family_id=session.family_id,
                    correlation_id=correlation_id
                )
                await self._event_publisher.publish(event)
                
        except Exception as e:
            logger.error(
                "Failed to handle session expiration",
                jti=session.jti,
                user_id=session.user_id,
                error=str(e)
            ) 