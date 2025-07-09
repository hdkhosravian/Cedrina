"""Database connection settings.
"""

import logging

from pydantic import Field, SecretStr, ValidationInfo, field_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


class DatabaseSettings(BaseSettings):
    """Defines settings for connecting to the PostgreSQL database.

    Security Note:
        - POSTGRES_PASSWORD and PGCRYPTO_KEY must be securely stored and never
          logged or exposed in version control
          (OWASP A02:2021 - Cryptographic Failures).
        - Use SSL_MODE 'verify-full' in production with proper certificate
          validation to prevent man-in-the-middle attacks.
    Performance Note:
        - Tune POSTGRES_POOL_SIZE and POSTGRES_MAX_OVERFLOW based on application
          load and database server capacity to optimize connection handling.
        - Adjust POSTGRES_POOL_TIMEOUT to balance between wait times and
          resource usage.
    """

    POSTGRES_USER: str
    POSTGRES_PASSWORD: SecretStr
    POSTGRES_DB: str
    POSTGRES_DB_TEST: str
    POSTGRES_HOST: str
    POSTGRES_PORT: int = Field(ge=1, le=65535, default=5432)
    POSTGRES_SSL_MODE: str = Field(
        pattern="^(disable|allow|prefer|require|verify-ca|verify-full)$", default="prefer"
    )
    POSTGRES_POOL_SIZE: int = Field(ge=1, default=10)
    POSTGRES_MAX_OVERFLOW: int = Field(ge=0, default=20)
    POSTGRES_POOL_TIMEOUT: float = Field(ge=1.0, default=5.0)
    DATABASE_URL: str = ""
    TEST_DATABASE_URL: str = ""
    PGCRYPTO_KEY: SecretStr
    EMAIL_CONFIRMATION_ENABLED: bool = False

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_db_url(cls, v: str | None, info: ValidationInfo) -> str:
        """Assembles the database connection URL if not provided explicitly.
        Ensures sensitive data like passwords are handled securely.

        Args:
            v: Explicitly provided URL or None.
            info: Validation context with other field values.

        Returns:
            Assembled or provided database URL.

        """
        if v:
            return v

        values = info.data
        password = values.get("POSTGRES_PASSWORD")
        if not password:
            logger.warning("POSTGRES_PASSWORD not set during DATABASE_URL assembly.")

        url = (
            f"postgresql+psycopg2://{values.get('POSTGRES_USER')}:"
            f"{password}@{values.get('POSTGRES_HOST')}:"
            f"{values.get('POSTGRES_PORT')}/{values.get('POSTGRES_DB')}"
        )
        logger.debug("Assembled DATABASE_URL (password masked for " "security).")
        return url

    @field_validator("TEST_DATABASE_URL", mode="before")
    @classmethod
    def assemble_test_db_url(cls, v: str | None, info: ValidationInfo) -> str:
        """Assembles the test database connection URL if not provided explicitly.
        Ensures sensitive data like passwords are handled securely.

        Args:
            v: Explicitly provided URL or None.
            info: Validation context with other field values.

        Returns:
            Assembled or provided test database URL.

        """
        if v:
            return v

        values = info.data
        password = values.get("POSTGRES_PASSWORD")
        if not password:
            logger.warning("POSTGRES_PASSWORD not set during TEST_DATABASE_URL assembly.")

        url = (
            f"postgresql+psycopg2://{values.get('POSTGRES_USER')}:"
            f"{password}@{values.get('POSTGRES_HOST')}:"
            f"{values.get('POSTGRES_PORT')}/{values.get('POSTGRES_DB_TEST')}"
        )
        logger.debug("Assembled TEST_DATABASE_URL (password masked for " "security).")
        return url
