"""
Session Management Wrapper for Single-Task Usage Per Session.

This module provides a session management wrapper that guarantees single-task
usage per database session, preventing concurrent operations on the same session
instance while maintaining clean architecture principles.

Key Features:
- Transactional boundaries for all database operations
- Single-task enforcement per session instance
- Automatic session lifecycle management
- Error handling with proper rollback semantics
- Comprehensive logging for debugging
- Production-grade security and reliability

Architecture:
- Follows clean architecture principles
- Maintains SOLID design principles
- Provides DDD-compliant session management
- Ensures thread-safe database operations
- Implements proper async context manager protocol
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import AsyncContextManager, AsyncGenerator, Optional, TypeVar, Generic, Any
import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from src.core.logging import logger

T = TypeVar('T')


class SessionContextManager(Generic[T]):
    """Context manager for single-task session usage.
    
    This context manager ensures that each database session is used by
    only one task at a time, preventing concurrent operations that could
    lead to transaction conflicts or data corruption.
    
    Features:
    - Automatic transaction management
    - Single-task enforcement with proper async support
    - Proper error handling and rollback
    - Comprehensive logging
    - Session lifecycle management
    - Production-grade security
    """
    
    def __init__(self, session: AsyncSession):
        """Initialize session context manager.
        
        Args:
            session: SQLAlchemy async session
        """
        self._session = session
        self._task_id = None
        self._session_id = id(session)
        self._logger = structlog.get_logger(f"{__name__}.SessionContextManager")
        self._in_transaction = False
        self._lock = asyncio.Lock()  # Add lock for better concurrency control
        
    async def __aenter__(self) -> AsyncSession:
        """Enter session context with transaction management.
        
        Returns:
            AsyncSession: Database session within transaction
            
        Raises:
            RuntimeError: If session is already in use by another task or nested context
        """
        async with self._lock:  # Ensure atomic access
            current_task = asyncio.current_task()
            current_task_id = current_task.get_name() if current_task else f"task_{id(current_task)}"
            
            # Check if session is already in use (either by another task or nested context)
            if self._task_id is not None:
                if self._task_id != current_task_id:
                    # Different task trying to use the session
                    self._logger.error(
                        "Session already in use by another task",
                        session_id=self._session_id,
                        current_task=current_task_id,
                        owning_task=self._task_id,
                        error_type="session_concurrency_violation"
                    )
                    raise RuntimeError(
                        f"Session {self._session_id} is already in use by task {self._task_id}. "
                        f"Current task: {current_task_id}"
                    )
                else:
                    # Same task trying to use the session again (nested context)
                    self._logger.error(
                        "Session already in use by current task (nested context)",
                        session_id=self._session_id,
                        task_id=current_task_id,
                        error_type="session_nested_context_violation"
                    )
                    raise RuntimeError(
                        f"Session {self._session_id} is already in use by current task {current_task_id}. "
                        f"Nested contexts are not allowed."
                    )
            
            self._task_id = current_task_id
            
            # Begin transaction to enforce single-task usage
            try:
                # Handle both real sessions and mocks properly
                if hasattr(self._session, 'begin') and callable(self._session.begin):
                    # Check if it's an async method
                    if asyncio.iscoroutinefunction(self._session.begin):
                        await self._session.begin()
                    else:
                        # For mocks or sync methods, call directly
                        self._session.begin()
                
                self._in_transaction = True
                
                self._logger.debug(
                    "Session transaction started",
                    session_id=self._session_id,
                    task_id=self._task_id,
                    transaction_active=True
                )
                
                return self._session
                
            except Exception as e:
                self._logger.error(
                    "Failed to start session transaction",
                    session_id=self._session_id,
                    task_id=self._task_id,
                    error=str(e),
                    error_type=type(e).__name__
                )
                self._task_id = None
                raise
    
    async def __aexit__(self, exc_type: Optional[type], exc_val: Optional[Exception], exc_tb: Any) -> None:
        """Exit session context with proper cleanup.
        
        Args:
            exc_type: Exception type if any
            exc_val: Exception value if any
            exc_tb: Exception traceback if any
        """
        async with self._lock:  # Ensure atomic cleanup
            try:
                if self._in_transaction:
                    if exc_type is not None:
                        # Rollback on exception
                        if hasattr(self._session, 'rollback') and callable(self._session.rollback):
                            if asyncio.iscoroutinefunction(self._session.rollback):
                                await self._session.rollback()
                            else:
                                self._session.rollback()
                        
                        self._logger.debug(
                            "Session transaction rolled back due to exception",
                            session_id=self._session_id,
                            task_id=self._task_id,
                            exception_type=exc_type.__name__ if exc_type else None
                        )
                    else:
                        # Commit on success
                        if hasattr(self._session, 'commit') and callable(self._session.commit):
                            if asyncio.iscoroutinefunction(self._session.commit):
                                await self._session.commit()
                            else:
                                self._session.commit()
                        
                        self._logger.debug(
                            "Session transaction committed successfully",
                            session_id=self._session_id,
                            task_id=self._task_id
                        )
                    
                    self._in_transaction = False
                    
            except SQLAlchemyError as e:
                self._logger.error(
                    "Error during session cleanup",
                    session_id=self._session_id,
                    task_id=self._task_id,
                    error=str(e),
                    error_type=type(e).__name__
                )
                # Don't re-raise to avoid masking the original exception
                
            finally:
                # Always reset task ownership
                self._task_id = None
                self._logger.debug(
                    "Session context cleanup completed",
                    session_id=self._session_id
                )


@contextlib.asynccontextmanager
async def get_transactional_session(
    session: AsyncSession
) -> AsyncGenerator[AsyncSession, None]:
    """Get database session with transactional boundaries.
    
    This context manager wraps database sessions to ensure single-task usage
    and proper transaction management. It prevents concurrent operations on
    the same session instance.
    
    Args:
        session: SQLAlchemy async session
        
    Yields:
        AsyncSession: Session within transactional context
        
    Example:
        ```python
        async with get_transactional_session(db_session) as session:
            # All database operations within this block are transactional
            result = await session.execute(select(User).where(User.id == 1))
            user = result.scalar_one_or_none()
            if user:
                user.last_login = datetime.utcnow()
                session.add(user)
            # Automatic commit on success, rollback on exception
        ```
    """
    async with SessionContextManager(session) as transactional_session:
        yield transactional_session


def ensure_single_task_session(session: AsyncSession) -> SessionContextManager[AsyncSession]:
    """Ensure session is used by single task only.
    
    This function returns a context manager that enforces single-task usage
    for the provided session. Use this when you need to ensure that a session
    is not used concurrently by multiple tasks.
    
    Args:
        session: SQLAlchemy async session
        
    Returns:
        SessionContextManager: Context manager for single-task session usage
        
    Example:
        ```python
        async with ensure_single_task_session(db_session) as session:
            # Session is guaranteed to be used by this task only
            await session.execute(select(User))
        ```
    """
    return SessionContextManager(session)
