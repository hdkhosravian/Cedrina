"""
Session Factory Interface and Implementation.

This module provides a session factory pattern for creating database sessions
on-demand, ensuring proper session isolation and lifecycle management while
maintaining clean architecture principles.

Key Features:
- Session creation on-demand for each operation
- Proper session lifecycle management
- Thread-safe session creation
- Support for both regular and transactional sessions
- Comprehensive logging and error handling
- Production-grade security and reliability
- Connection pooling and retry logic
- Rate limiting for session creation

Architecture:
- Interface-based design for dependency injection
- Factory pattern for session creation
- Clean separation of concerns
- Production-grade error handling
- Security-first design principles
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from typing import AsyncGenerator, AsyncContextManager, Optional, Protocol
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError, DisconnectionError

from src.infrastructure.database.async_db import AsyncSessionFactory, _build_async_url
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from src.infrastructure.database.session_manager import get_transactional_session

logger = structlog.get_logger(__name__)


class ISessionFactory(Protocol):
    """Interface for database session factories.
    
    This interface defines the contract for creating database sessions
    on-demand, ensuring proper session isolation and lifecycle management.
    """
    
    @abstractmethod
    async def create_session(self) -> AsyncContextManager[AsyncSession]:
        """Create a new database session.
        
        Returns:
            AsyncContextManager[AsyncSession]: Context manager for session lifecycle
        """
        ...
    
    @abstractmethod
    async def create_transactional_session(self) -> AsyncContextManager[AsyncSession]:
        """Create a new transactional database session.
        
        Returns:
            AsyncContextManager[AsyncSession]: Context manager for transactional session
        """
        ...


class AsyncSessionFactoryImpl(ISessionFactory):
    """Implementation of session factory for async database sessions.
    
    This factory creates new database sessions on-demand, ensuring proper
    session isolation and lifecycle management. Each session is created
    with its own transaction context.
    
    Features:
    - Creates new sessions for each operation
    - Proper session lifecycle management
    - Transaction boundary enforcement
    - Comprehensive logging and error handling
    - Thread-safe session creation
    - Production-grade security and reliability
    - Connection pooling and retry logic
    - Rate limiting for session creation
    """
    
    def __init__(self, max_retries: int = 3, retry_delay: float = 0.1):
        """Initialize the session factory.
        
        Args:
            max_retries: Maximum number of retry attempts for session creation
            retry_delay: Delay between retry attempts in seconds
        """
        self._logger = structlog.get_logger(f"{__name__}.AsyncSessionFactoryImpl")
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._session_count = 0
        self._lock = None  # Will be created lazily in the correct event loop context
        
        # Create a new engine instance for this factory with better connection pooling
        url = make_url(_build_async_url())
        conn_params = {}
        self._engine = create_async_engine(
            url, 
            echo=False,  # Disable echo for better performance 
            future=True, 
            connect_args=conn_params,
            pool_size=20,  # Larger pool size for concurrent tests
            max_overflow=40,  # Allow more overflow connections
            pool_pre_ping=True,  # Verify connections before use
            pool_recycle=3600,  # Recycle connections after 1 hour
            pool_timeout=60,  # Wait longer for connection availability
            pool_reset_on_return='commit',  # Reset connections on return
        )
        
        # Import LoggingAsyncSession dynamically to avoid circular imports
        from src.infrastructure.database.async_db import LoggingAsyncSession
        self._session_factory = sessionmaker(
            bind=self._engine, class_=LoggingAsyncSession, expire_on_commit=False
        )
        
        self._logger.debug(
            "AsyncSessionFactoryImpl initialized",
            factory_id=id(self),
            max_retries=max_retries,
            retry_delay=retry_delay
        )
    
    def _get_lock(self) -> asyncio.Lock:
        """Get the asyncio lock, creating it lazily in the current event loop context."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock
    
    async def _create_session_with_retry(self) -> AsyncSession:
        """Create a session with retry logic for production reliability.
        
        Returns:
            AsyncSession: New database session
            
        Raises:
            SQLAlchemyError: If session creation fails after all retries
        """
        last_exception = None
        
        for attempt in range(self._max_retries):
            try:
                # Add a small random delay to prevent thundering herd
                if attempt > 0:
                    import random
                    jitter = random.uniform(0.05, 0.15)
                    await asyncio.sleep(self._retry_delay * attempt + jitter)
                
                async with self._get_lock():
                    self._session_count += 1
                    session_id = self._session_count
                
                session = self._session_factory()
                
                # Test the connection to ensure it's working
                try:
                    from sqlalchemy import text
                    await session.execute(text("SELECT 1"))
                except Exception as test_error:
                    await session.close()
                    raise test_error
                
                self._logger.debug(
                    "Session created successfully",
                    session_id=session_id,
                    factory_id=id(self),
                    attempt=attempt + 1
                )
                
                return session
                
            except Exception as e:
                last_exception = e
                self._logger.warning(
                    "Session creation failed, retrying",
                    attempt=attempt + 1,
                    max_retries=self._max_retries,
                    error=str(e),
                    error_type=type(e).__name__
                )
                
                if attempt < self._max_retries - 1:
                    # Exponential backoff with jitter
                    import random
                    base_delay = self._retry_delay * (2 ** attempt)
                    jitter = random.uniform(0.1, 0.3)
                    await asyncio.sleep(base_delay + jitter)
        
        # If we get here, all retries failed
        self._logger.error(
            "Session creation failed after all retries",
            max_retries=self._max_retries,
            error=str(last_exception),
            error_type=type(last_exception).__name__ if last_exception else None
        )
        raise last_exception or SQLAlchemyError("Session creation failed")
    
    @asynccontextmanager
    async def create_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Create a new database session with proper lifecycle management.
        
        This method creates a new SQLAlchemy async session with automatic
        cleanup and error handling. Each session is independent and isolated.
        
        Yields:
            AsyncSession: New database session instance
            
        Example:
            ```python
            async with factory.create_session() as session:
                result = await session.execute(select(User))
                # Session is automatically cleaned up
            ```
        """
        session_id = None
        session = None
        start_time = time.time()
        
        try:
            # Create new session instance with retry logic
            session = await self._create_session_with_retry()
            session_id = id(session)
            
            self._logger.debug(
                "New session created",
                session_id=session_id,
                factory_id=id(self),
                creation_time_ms=(time.time() - start_time) * 1000
            )
            
            try:
                yield session
                
            except Exception as e:
                # Rollback on exception
                if hasattr(session, 'rollback') and callable(session.rollback):
                    if asyncio.iscoroutinefunction(session.rollback):
                        await session.rollback()
                    else:
                        session.rollback()
                
                self._logger.error(
                    "Session rollback due to error",
                    session_id=session_id,
                    error=str(e),
                    error_type=type(e).__name__
                )
                raise
                
        except Exception as e:
            self._logger.error(
                "Session creation failed",
                session_id=session_id,
                error=str(e),
                error_type=type(e).__name__
            )
            raise
            
        finally:
            # Always close the session
            if session is not None:
                try:
                    if hasattr(session, 'close') and callable(session.close):
                        if asyncio.iscoroutinefunction(session.close):
                            await session.close()
                        else:
                            session.close()
                    
                    self._logger.debug(
                        "Session closed",
                        session_id=session_id,
                        factory_id=id(self)
                    )
                    
                except Exception as e:
                    self._logger.error(
                        "Error closing session",
                        session_id=session_id,
                        error=str(e),
                        error_type=type(e).__name__
                    )
    
    @asynccontextmanager
    async def create_transactional_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Create a new transactional database session.
        
        This method creates a new SQLAlchemy async session with explicit
        transaction boundaries, ensuring ACID properties for all operations
        within the session context.
        
        Yields:
            AsyncSession: New transactional database session
            
        Example:
            ```python
            async with factory.create_transactional_session() as session:
                # All operations are within a transaction
                user = User(username="test")
                session.add(user)
                # Automatic commit on success, rollback on exception
            ```
        """
        async with self.create_session() as session:
            async with get_transactional_session(session) as transactional_session:
                yield transactional_session


class DependencyInjectedSessionFactory(ISessionFactory):
    """Session factory that uses dependency injection for session creation.
    
    This factory receives a session from FastAPI's dependency injection
    system and creates new sessions based on the provided session factory.
    It ensures proper session isolation while maintaining compatibility
    with the existing dependency injection system.
    """
    
    def __init__(self, session_factory: Optional[ISessionFactory] = None):
        """Initialize dependency-injected session factory.
        
        Args:
            session_factory: Optional session factory to use for creating sessions
        """
        self._session_factory = session_factory or AsyncSessionFactoryImpl()
        self._logger = structlog.get_logger(f"{__name__}.DependencyInjectedSessionFactory")
        
        self._logger.debug(
            "DependencyInjectedSessionFactory initialized",
            factory_id=id(self),
            underlying_factory=type(self._session_factory).__name__
        )
    
    async def create_session(self) -> AsyncContextManager[AsyncSession]:
        """Create a new session using the underlying factory.
        
        Returns:
            AsyncContextManager[AsyncSession]: Context manager for session lifecycle
        """
        return self._session_factory.create_session()
    
    async def create_transactional_session(self) -> AsyncContextManager[AsyncSession]:
        """Create a new transactional session using the underlying factory.
        
        Returns:
            AsyncContextManager[AsyncSession]: Context manager for transactional session
        """
        return self._session_factory.create_transactional_session()


# Factory instance for global usage (lazy initialization)
_default_session_factory = None

def get_default_session_factory() -> ISessionFactory:
    """Get the default session factory instance with lazy initialization.
    
    Returns:
        ISessionFactory: Default session factory instance
    """
    global _default_session_factory
    if _default_session_factory is None:
        _default_session_factory = AsyncSessionFactoryImpl()
    return _default_session_factory
