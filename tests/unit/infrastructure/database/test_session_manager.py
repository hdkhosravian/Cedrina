"""
Unit tests for Session Management Wrapper.

This module tests the session management wrapper that guarantees single-task
usage per database session, preventing concurrent operations on the same session
instance while maintaining clean architecture principles.

Test Coverage:
- Single-task enforcement
- Transactional boundaries
- Error handling and rollback
- Session lifecycle management
- Concurrent access prevention
- Logging and monitoring
- Production-grade scenarios
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from src.infrastructure.database.session_manager import (
    SessionContextManager,
    get_transactional_session,
    ensure_single_task_session,
)


class TestSessionContextManager:
    """Test the session context manager for single-task usage."""
    
    @pytest.fixture
    def mock_session(self):
        """Create a properly mocked async session."""
        session = AsyncMock(spec=AsyncSession)
        
        # Mock async context manager methods
        session.begin = AsyncMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.close = AsyncMock()
        
        # Ensure all async methods are properly mocked
        session.begin.return_value = None
        session.commit.return_value = None
        session.rollback.return_value = None
        session.close.return_value = None
        
        return session
    
    @pytest.fixture
    def context_manager(self, mock_session):
        """Create a session context manager."""
        return SessionContextManager(mock_session)
    
    async def test_single_task_usage_success(self, context_manager, mock_session):
        """Test successful single-task usage."""
        async with context_manager as session:
            assert session is mock_session
            mock_session.begin.assert_called_once()
        
        mock_session.commit.assert_called_once()
        mock_session.rollback.assert_not_called()
    
    async def test_single_task_usage_with_exception(self, context_manager, mock_session):
        """Test single-task usage with exception handling."""
        test_error = Exception("Test error")
        
        with pytest.raises(Exception):
            async with context_manager as session:
                mock_session.begin.assert_called_once()
                raise test_error
        
        mock_session.rollback.assert_called_once()
        mock_session.commit.assert_not_called()
    
    async def test_concurrent_access_prevention(self, mock_session):
        """Test that concurrent access to the same session is prevented."""
        context_manager = SessionContextManager(mock_session)
        
        # Create a task that holds the session
        async def hold_session():
            async with context_manager as session:
                # Simulate some work
                await asyncio.sleep(0.01)
                return session
        
        # Create a task that tries to access the same session
        async def try_access_session():
            async with context_manager as session:
                return session
        
        # Start the first task
        task1 = asyncio.create_task(hold_session())
        
        # Wait a bit and then try to access the session from another task
        await asyncio.sleep(0.005)
        
        # This should raise RuntimeError
        with pytest.raises(RuntimeError) as exc_info:
            await try_access_session()
        
        assert "already in use" in str(exc_info.value)
        
        # Wait for the first task to complete
        await task1
    
    async def test_task_cleanup_after_completion(self, mock_session):
        """Test that task ownership is cleaned up after completion."""
        context_manager = SessionContextManager(mock_session)
        
        # First usage
        async with context_manager as session1:
            assert session1 is mock_session
        
        # Second usage should work after cleanup
        async with context_manager as session2:
            assert session2 is mock_session
        
        # Both calls should have started transactions
        assert mock_session.begin.call_count == 2
    
    async def test_rollback_on_sqlalchemy_error(self, mock_session):
        """Test rollback when SQLAlchemy error occurs."""
        context_manager = SessionContextManager(mock_session)
        sql_error = SQLAlchemyError("Database error")
        
        with pytest.raises(SQLAlchemyError):
            async with context_manager as session:
                raise sql_error
        
        mock_session.rollback.assert_called_once()
        mock_session.commit.assert_not_called()
    
    async def test_session_begin_failure(self, mock_session):
        """Test handling of session.begin() failure."""
        context_manager = SessionContextManager(mock_session)
        begin_error = SQLAlchemyError("Begin failed")
        mock_session.begin.side_effect = begin_error
        
        with pytest.raises(SQLAlchemyError):
            async with context_manager as session:
                pass
        
        # Should not attempt commit or rollback if begin failed
        mock_session.commit.assert_not_called()
        mock_session.rollback.assert_not_called()
    
    async def test_commit_failure_handling(self, mock_session):
        """Test handling of commit failure."""
        context_manager = SessionContextManager(mock_session)
        commit_error = SQLAlchemyError("Commit failed")
        mock_session.commit.side_effect = commit_error
        
        # Should not raise the commit error (logged but not re-raised)
        async with context_manager as session:
            pass
        
        mock_session.commit.assert_called_once()
        mock_session.rollback.assert_not_called()
    
    async def test_rollback_failure_handling(self, mock_session):
        """Test handling of rollback failure."""
        context_manager = SessionContextManager(mock_session)
        rollback_error = SQLAlchemyError("Rollback failed")
        mock_session.rollback.side_effect = rollback_error
        
        # Should not raise the rollback error (logged but not re-raised)
        with pytest.raises(Exception):
            async with context_manager as session:
                raise Exception("Original error")
        
        mock_session.rollback.assert_called_once()
        mock_session.commit.assert_not_called()
    
    @patch('src.infrastructure.database.session_manager.structlog')
    async def test_logging_integration(self, mock_structlog, mock_session):
        """Test that operations are properly logged."""
        mock_logger = MagicMock()
        mock_structlog.get_logger.return_value = mock_logger
        
        context_manager = SessionContextManager(mock_session)
        
        async with context_manager as session:
            pass
        
        # Verify logging calls
        mock_structlog.get_logger.assert_called()
        mock_logger.debug.assert_called()
    
    async def test_session_id_tracking(self, mock_session):
        """Test that session ID is properly tracked."""
        context_manager = SessionContextManager(mock_session)
        
        assert context_manager._session_id == id(mock_session)
        assert context_manager._session is mock_session
    
    async def test_task_id_tracking(self, mock_session):
        """Test that task ID is properly tracked."""
        context_manager = SessionContextManager(mock_session)
        
        async with context_manager as session:
            # Task ID should be set when context is entered
            assert context_manager._task_id is not None
        
        # Task ID should be cleared when context is exited
        assert context_manager._task_id is None


class TestGetTransactionalSession:
    """Test the get_transactional_session context manager."""
    
    async def test_transactional_session_wrapper(self):
        """Test that the transactional session wrapper works correctly."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_session.begin = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        
        async with get_transactional_session(mock_session) as session:
            assert session is mock_session
            mock_session.begin.assert_called_once()
        
        mock_session.commit.assert_called_once()
        mock_session.rollback.assert_not_called()
    
    async def test_transactional_session_with_exception(self):
        """Test transactional session with exception handling."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_session.begin = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        
        with pytest.raises(Exception):
            async with get_transactional_session(mock_session) as session:
                raise Exception("Test error")
        
        mock_session.rollback.assert_called_once()
        mock_session.commit.assert_not_called()


class TestEnsureSingleTaskSession:
    """Test the ensure_single_task_session function."""
    
    async def test_ensure_single_task_session_returns_context_manager(self):
        """Test that ensure_single_task_session returns a context manager."""
        mock_session = AsyncMock(spec=AsyncSession)
        
        context_manager = ensure_single_task_session(mock_session)
        
        assert isinstance(context_manager, SessionContextManager)
        assert context_manager._session is mock_session
    
    async def test_ensure_single_task_session_usage(self):
        """Test using the context manager returned by ensure_single_task_session."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_session.begin = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        
        async with ensure_single_task_session(mock_session) as session:
            assert session is mock_session
            mock_session.begin.assert_called_once()
        
        mock_session.commit.assert_called_once()
        mock_session.rollback.assert_not_called()


class TestConcurrentScenarios:
    """Test concurrent access scenarios."""
    
    async def test_multiple_tasks_sequential_access(self):
        """Test that multiple tasks can access session sequentially."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_session.begin = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        
        context_manager = SessionContextManager(mock_session)
        
        # First task
        async with context_manager as session1:
            assert session1 is mock_session
        
        # Second task (should work after first task completes)
        async with context_manager as session2:
            assert session2 is mock_session
        
        # Both should have started transactions
        assert mock_session.begin.call_count == 2
        assert mock_session.commit.call_count == 2
    
    async def test_different_sessions_concurrent_access(self):
        """Test that different sessions can be accessed concurrently."""
        mock_session1 = AsyncMock(spec=AsyncSession)
        mock_session1.begin = AsyncMock()
        mock_session1.commit = AsyncMock()
        mock_session1.rollback = AsyncMock()
        
        mock_session2 = AsyncMock(spec=AsyncSession)
        mock_session2.begin = AsyncMock()
        mock_session2.commit = AsyncMock()
        mock_session2.rollback = AsyncMock()
        
        context_manager1 = SessionContextManager(mock_session1)
        context_manager2 = SessionContextManager(mock_session2)
        
        # Both tasks should be able to run concurrently
        async def task1():
            async with context_manager1 as session:
                await asyncio.sleep(0.01)
                return session
        
        async def task2():
            async with context_manager2 as session:
                await asyncio.sleep(0.01)
                return session
        
        # Run both tasks concurrently
        results = await asyncio.gather(task1(), task2())
        
        assert results[0] is mock_session1
        assert results[1] is mock_session2
        
        # Both sessions should have been used
        mock_session1.begin.assert_called_once()
        mock_session2.begin.assert_called_once()


class TestErrorScenarios:
    """Test error handling scenarios."""
    
    async def test_session_reuse_after_error(self):
        """Test that session can be reused after an error."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_session.begin = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        
        context_manager = SessionContextManager(mock_session)
        
        # First usage with error
        with pytest.raises(Exception):
            async with context_manager as session:
                raise Exception("Test error")
        
        # Second usage should work
        async with context_manager as session:
            pass
        
        # Should have called rollback once and commit once
        assert mock_session.rollback.call_count == 1
        assert mock_session.commit.call_count == 1
    
    async def test_nested_context_prevention(self):
        """Test that nested contexts are prevented."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_session.begin = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        
        context_manager = SessionContextManager(mock_session)
        
        async with context_manager as session1:
            # Nested context should fail
            with pytest.raises(RuntimeError) as exc_info:
                async with context_manager as session2:
                    pass
            
            assert "already in use" in str(exc_info.value)


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""
    
    async def test_database_operation_simulation(self):
        """Test simulation of real database operations."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_session.begin = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()
        
        async with get_transactional_session(mock_session) as session:
            # Simulate database operations
            await session.execute("SELECT 1")
            session.add("mock_entity")
            await session.flush()
        
        # Verify all operations were called
        mock_session.begin.assert_called_once()
        mock_session.execute.assert_called_once()
        mock_session.add.assert_called_once()
        mock_session.flush.assert_called_once()
        mock_session.commit.assert_called_once()
    
    async def test_transaction_rollback_on_flush_error(self):
        """Test rollback when flush operation fails."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_session.begin = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        mock_session.flush = AsyncMock(side_effect=SQLAlchemyError("Flush failed"))
        
        with pytest.raises(SQLAlchemyError):
            async with get_transactional_session(mock_session) as session:
                await session.flush()
        
        mock_session.begin.assert_called_once()
        mock_session.flush.assert_called_once()
        mock_session.rollback.assert_called_once()
        mock_session.commit.assert_not_called()
    
    async def test_performance_with_multiple_operations(self):
        """Test performance with multiple concurrent operations."""
        mock_sessions = [AsyncMock(spec=AsyncSession) for _ in range(5)]
        for session in mock_sessions:
            session.begin = AsyncMock()
            session.commit = AsyncMock()
            session.rollback = AsyncMock()
            session.execute = AsyncMock()
        
        context_managers = [SessionContextManager(session) for session in mock_sessions]
        
        async def operation(context_manager):
            async with context_manager as session:
                await session.execute("SELECT 1")
                await asyncio.sleep(0.001)  # Simulate work
        
        # Run multiple operations concurrently
        await asyncio.gather(*[operation(cm) for cm in context_managers])
        
        # All sessions should have been used
        for session in mock_sessions:
            session.begin.assert_called_once()
            session.commit.assert_called_once()
            session.execute.assert_called_once()
