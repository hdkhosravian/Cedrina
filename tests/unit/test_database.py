import pytest
from sqlalchemy.sql import text
from sqlmodel import Session

from src.core.config.settings import settings
from src.infrastructure.database import check_database_health, engine


def test_database_connectivity():
    assert check_database_health()
    with Session(engine) as session:
        assert session.bind is not None
        assert session.exec(text("SELECT 1")).scalar_one() == 1


def test_database_settings(monkeypatch):
    monkeypatch.setenv("POSTGRES_DB", "cedrina_test")
    # We need to reload the settings, but for this simple case, we can just patch it
    monkeypatch.setattr(settings, "POSTGRES_DB", "cedrina_test")

    assert settings.POSTGRES_POOL_SIZE == 20
    assert settings.POSTGRES_MAX_OVERFLOW == 30
    assert settings.POSTGRES_POOL_TIMEOUT == 30.0
    assert settings.POSTGRES_SSL_MODE == "disable"
    assert settings.POSTGRES_DB == "cedrina_test"


@pytest.mark.asyncio
async def test_database_health_check_success(mocker):
    """Test successful database health check."""
    mock_session = mocker.MagicMock()
    mock_exec_result = mocker.MagicMock()
    mock_session.exec = mocker.MagicMock(return_value=mock_exec_result)

    def mock_get_db_session():
        class MockContextManager:
            def __enter__(self):
                return mock_session

            def __exit__(self, exc_type, exc_val, exc_tb):
                pass

        return MockContextManager()

    mocker.patch("infrastructure.database.database.get_db_session", side_effect=mock_get_db_session)
    mocker.patch("infrastructure.database.database.logger.info")

    from infrastructure.database.database import check_database_health

    result = check_database_health()
    assert result is True
    mock_session.exec.assert_called_once()


@pytest.mark.asyncio
async def test_database_health_check_failure(mocker):
    """Test database health check failure."""
    mocker.patch(
        "infrastructure.database.database.get_db_session",
        side_effect=Exception("Connection failed"),
    )
    mocker.patch("infrastructure.database.database.logger.error")

    from infrastructure.database.database import check_database_health

    result = check_database_health()
    assert result is False


@pytest.mark.asyncio
async def test_log_query_execution_success(mocker):
    """Test logging of successful query execution."""
    mock_logger_debug = mocker.patch("infrastructure.database.database.logger.debug")

    from infrastructure.database.database import log_query_execution

    log_query_execution("SELECT * FROM users", {"id": 1}, 0.01)
    mock_logger_debug.assert_called_once()


@pytest.mark.asyncio
async def test_log_query_execution_error(mocker):
    """Test logging of query execution with error."""
    mock_logger_error = mocker.patch("infrastructure.database.database.logger.error")
    error = Exception("Query failed")

    from infrastructure.database.database import log_query_execution

    log_query_execution("SELECT * FROM users", {"id": 1}, 0.01, error)
    mock_logger_error.assert_called_once()


@pytest.mark.asyncio
async def test_get_db_session_error_handling(mocker):
    """Test error handling in get_db_session context manager."""
    mocker.patch(
        "infrastructure.database.database.Session", side_effect=Exception("Session creation failed")
    )

    from infrastructure.database.database import get_db_session

    with pytest.raises(Exception):
        with get_db_session() as session:
            pass


def test_get_db_rollback_on_error(mocker):
    """Test that get_db handles exceptions properly."""
    mock_session = mocker.MagicMock()

    # Mock the get_db_session context manager
    mock_context_manager = mocker.patch("infrastructure.database.database.get_db_session")
    mock_context_manager.return_value.__enter__.return_value = mock_session

    from infrastructure.database.database import get_db

    db_generator = get_db()
    session = next(db_generator)

    # Expect an exception to be raised when we throw one into the generator
    with pytest.raises(Exception, match="Test error"):
        db_generator.throw(Exception("Test error"))

    # Assert that rollback was called
    mock_session.rollback.assert_called_once()
