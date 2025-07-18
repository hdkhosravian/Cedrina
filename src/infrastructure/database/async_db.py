from __future__ import annotations

"""
Asynchronous Database Utilities Module

This module provides asynchronous database utilities using SQLAlchemy's asyncio support, complementing
the synchronous utilities in 'database.py'. It is specifically designed for components like authentication
endpoints that require asynchronous database access for better performance and scalability in high-concurrency
environments.

The synchronous engine is retained for background jobs and test suites, but this module exposes minimal
helpers for async operations without altering existing synchronous code paths.

**Security Note**: Ensure that the database connection URL (DATABASE_URL) is configured for SSL/TLS when
connecting over untrusted networks to prevent data interception (OWASP A02:2021 - Cryptographic Failures).
Note that asyncpg handles SSL differently, and 'sslmode' is not directly supported in connect_args; it must
be specified in the URL if required. Avoid logging sensitive connection details to prevent information
disclosure (OWASP A09:2021 - Security Logging and Monitoring Failures). Use least privilege principles for
database accounts.

Key Components:
    - engine: The asynchronous SQLAlchemy engine for PostgreSQL connections.
    - AsyncSessionFactory: A factory for creating asynchronous database sessions.
    - get_async_db: A context manager dependency for yielding async sessions.
    - create_async_db_and_tables: Utility to create tables using the async engine.
"""

import urllib.parse as urlparse
from contextlib import asynccontextmanager
from typing import AsyncGenerator
import asyncio

from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel
import structlog
from sqlalchemy import event
import time

from src.core.config.settings import settings
from src.core.logging import logger

# Configure logging for async database events
logger = structlog.get_logger(__name__)


# Construct the async database URL
def _build_async_url() -> str:
    """Build the asynchronous database URL with proper handling of SSL parameters.

    This function constructs the async database URL by replacing the driver with asyncpg
    and cleaning up query parameters like sslmode, which asyncpg handles differently.

    **Security Note**: Ensure SSL parameters are included in the URL if connecting over
    an untrusted network to prevent data interception.

    Returns:
        str: The cleaned asynchronous database URL.

    """
    async_url = settings.DATABASE_URL.replace("postgresql+psycopg2", "postgresql+asyncpg")
    # Strip sslmode from the URL if present, as asyncpg handles SSL differently
    parsed = urlparse.urlparse(async_url)
    query = dict(urlparse.parse_qsl(parsed.query))
    query.pop("sslmode", None)
    new_query = urlparse.urlencode(query)
    parsed = parsed._replace(query=new_query)
    cleaned_url = urlparse.urlunparse(parsed)
    return cleaned_url


url = make_url(_build_async_url())
conn_params = {}
# asyncpg does not support sslmode in connect_args, it's handled in the URL if needed
# Temporarily enable echo for debugging
engine = create_async_engine(
    url, 
    echo=False,  # Disable echo for production
    future=True, 
    connect_args=conn_params,
    pool_size=settings.POSTGRES_POOL_SIZE,  # Use consistent pool size from settings
    max_overflow=settings.POSTGRES_MAX_OVERFLOW,  # Use consistent overflow from settings
    pool_pre_ping=True,  # Verify connections before use
    pool_recycle=3600,  # Recycle connections after 1 hour
    pool_timeout=settings.POSTGRES_POOL_TIMEOUT,  # Use consistent timeout from settings
)

# Simple query performance monitoring
@event.listens_for(engine.sync_engine, "before_cursor_execute")
def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    """Monitor query execution time for performance optimization."""
    context._query_start_time = time.time()

@event.listens_for(engine.sync_engine, "after_cursor_execute")
def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    """Log slow queries for performance monitoring."""
    if hasattr(context, '_query_start_time'):
        total = time.time() - context._query_start_time
        if total > 0.1:  # Log queries taking more than 100ms
            logger.warning(
                "Slow query detected",
                duration_ms=round(total * 1000, 2),
                query=str(statement)[:200] + "..." if len(str(statement)) > 200 else str(statement)
            )

class LoggingAsyncSession(AsyncSession):
    """AsyncSession wrapper that logs all database operations with session and task tracking."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._logger = structlog.get_logger(f"{__name__}.LoggingAsyncSession")
        self._session_id = id(self)
        
        # Safely get task ID - handle case where no event loop is running
        try:
            current_task = asyncio.current_task()
            self._task_id = current_task.get_name() if current_task else "no_event_loop"
        except RuntimeError:
            # No event loop running during initialization
            self._task_id = "no_event_loop"
        
        self._logger.debug("Session initialized", session_id=self._session_id, task_id=self._task_id)
    
    async def execute(self, statement, parameters=None, execution_options=None, **kwargs):
        """Log every execute operation."""
        self._logger.debug(
            "Executing SQL statement", 
            session_id=self._session_id, 
            task_id=self._task_id,
            statement=str(statement)[:200] + "..." if len(str(statement)) > 200 else str(statement)
        )
        try:
            # Call parent execute with minimal arguments based on what's provided
            if execution_options is not None:
                result = await super().execute(statement, parameters, execution_options)
            elif parameters is not None:
                result = await super().execute(statement, parameters)
            else:
                result = await super().execute(statement)
            self._logger.debug(
                "SQL statement executed successfully", 
                session_id=self._session_id, 
                task_id=self._task_id
            )
            return result
        except Exception as e:
            self._logger.error(
                "SQL statement execution failed", 
                session_id=self._session_id, 
                task_id=self._task_id,
                error=str(e)
            )
            raise
    
    async def commit(self):
        """Log commit operations."""
        self._logger.debug("Committing transaction", session_id=self._session_id, task_id=self._task_id)
        try:
            await super().commit()
            self._logger.debug("Transaction committed successfully", session_id=self._session_id, task_id=self._task_id)
        except Exception as e:
            self._logger.error(
                "Transaction commit failed", 
                session_id=self._session_id, 
                task_id=self._task_id,
                error=str(e)
            )
            raise
    
    async def rollback(self):
        """Log rollback operations."""
        self._logger.debug("Rolling back transaction", session_id=self._session_id, task_id=self._task_id)
        try:
            await super().rollback()
            self._logger.debug("Transaction rolled back successfully", session_id=self._session_id, task_id=self._task_id)
        except Exception as e:
            self._logger.error(
                "Transaction rollback failed", 
                session_id=self._session_id, 
                task_id=self._task_id,
                error=str(e)
            )
            raise
    
    async def flush(self, objects=None):
        """Log flush operations."""
        self._logger.debug("Flushing session", session_id=self._session_id, task_id=self._task_id)
        try:
            await super().flush(objects)
            self._logger.debug("Session flushed successfully", session_id=self._session_id, task_id=self._task_id)
        except Exception as e:
            self._logger.error(
                "Session flush failed", 
                session_id=self._session_id, 
                task_id=self._task_id,
                error=str(e)
            )
            raise
    
    async def close(self):
        """Log close operations."""
        self._logger.debug("Closing session", session_id=self._session_id, task_id=self._task_id)
        try:
            await super().close()
            self._logger.debug("Session closed successfully", session_id=self._session_id, task_id=self._task_id)
        except Exception as e:
            self._logger.error(
                "Session close failed", 
                session_id=self._session_id, 
                task_id=self._task_id,
                error=str(e)
            )
            raise

AsyncSessionFactory: sessionmaker[AsyncSession] = sessionmaker(  # type: ignore[type-arg]
    bind=engine, class_=LoggingAsyncSession, expire_on_commit=False
)


@asynccontextmanager
async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an AsyncSession.

    This helper mirrors the behavior of 'get_db' from the synchronous database module.
    It automatically rolls back the transaction if an exception occurs and ensures proper
    session closure.

    **Security Note**: Avoid logging sensitive session details to prevent information disclosure.

    Yields:
        AsyncSession: An asynchronous database session for use in FastAPI routes.

    Example:
        To use this dependency in a FastAPI route:
        `@router.get('/data', dependencies=[Depends(get_async_db)])`

    """
    async with AsyncSessionFactory() as session:  # pragma: no cover – boilerplate
        logger.debug("Async database session created")
        try:
            yield session
        except Exception:
            await session.rollback()
            logger.error("Async database session rollback due to error")
            raise
        finally:
            await session.close()
            logger.debug("Async database session closed")


async def get_async_db_dependency() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency function that yields an AsyncSession.
    
    This is the proper FastAPI dependency function that can be used with Depends().
    It automatically manages the session lifecycle including rollback on errors.
    
    Yields:
        AsyncSession: An asynchronous database session for use in FastAPI routes.
    """
    async with AsyncSessionFactory() as session:
        try:
            current_task = asyncio.current_task()
            task_id = current_task.get_name() if current_task else "no_event_loop"
        except RuntimeError:
            task_id = "no_event_loop"
        logger.debug("Async database session created", session_id=id(session), task_id=task_id)
        try:
            yield session
        except Exception:
            await session.rollback()
            try:
                current_task = asyncio.current_task()
                task_id = current_task.get_name() if current_task else "no_event_loop"
            except RuntimeError:
                task_id = "no_event_loop"
            logger.error("Async database session rollback due to error", session_id=id(session), task_id=task_id)
            raise
        finally:
            await session.close()
            try:
                current_task = asyncio.current_task()
                task_id = current_task.get_name() if current_task else "no_event_loop"
            except RuntimeError:
                task_id = "no_event_loop"
            logger.debug("Async database session closed", session_id=id(session), task_id=task_id)


async def create_async_db_and_tables() -> None:
    """Create tables using the async engine (mainly for test suites).

        This function initializes database tables asynchronously, typically used during
    test setup or application initialization when async operations are preferred.
    """
    logger.info("Creating async database tables")
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    logger.info("Async database tables created")
