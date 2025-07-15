from datetime import datetime  # For timestamp fields
from typing import Optional  # For optional fields

from pydantic import ConfigDict, EmailStr, field_validator  # For email validation and custom validation
from sqlalchemy import DateTime, text  # For SQL expressions and explicit DateTime type
from sqlalchemy.dialects import postgresql  # Import PostgreSQL dialect
from sqlmodel import Column, Field, Index, SQLModel, String  # For ORM and table definition

from src.domain.entities.role import Role


class User(SQLModel, table=True):
    """Represents a User entity and acts as an Aggregate Root.

    This class models a user within the domain, encapsulating all properties
    and business rules related to a user's identity, authentication, and
    authorization. As an aggregate root, it is the primary object through which
    all user-related operations should be performed.

    The model supports both traditional password-based authentication and
    external OAuth providers.

    Attributes:
        id: The unique identifier for the user (primary key).
        username: A unique, case-insensitive username for login.
        email: A unique, case-insensitive email address.
        hashed_password: The securely hashed password (using bcrypt). Null for
            users who only authenticate via OAuth.
        role: The user's role, determining their permissions within the system.
        is_active: A flag indicating if the user's account is active. Inactive
            users cannot log in.
        created_at: The timestamp of when the user account was created.
        updated_at: The timestamp of the last update to the user's record.
        password_reset_token: A secure token for verifying a password reset request.
        password_reset_token_expires_at: The expiration timestamp for the reset token.
    """

    model_config = ConfigDict(
        validate_assignment=True,  # Enable validation on field assignment
        str_strip_whitespace=True,  # Strip whitespace from string fields
        validate_default=True,  # Validate default values
    )

    __tablename__ = "users"  # Explicit table name for clarity

    id: Optional[int] = Field(
        default=None,  # Auto-incremented by database
        primary_key=True,  # Primary key constraint
        description="The unique identifier for the user.",
    )
    username: str = Field(
        sa_column=Column(String, unique=True, index=True, nullable=False),  # Unique, indexed column
        min_length=3,  # Minimum length for security
        max_length=50,  # Maximum length for storage efficiency
        description="Unique, case-insensitive username for login.",
    )
    email: EmailStr = Field(
        sa_column=Column(String, unique=True, index=True, nullable=False),  # Unique, indexed column
        description="Unique, case-insensitive email address for communication and login.",
    )
    hashed_password: Optional[str] = Field(
        max_length=255,  # Sufficient for bcrypt hashes
        description="Bcrypt-hashed password. Null for users authenticating via OAuth.",
        default=None,  # Optional for OAuth users
    )
    role: Role = Field(
        sa_column=Column(
            postgresql.ENUM(Role, name="role", create_type=False),  # Use PostgreSQL enum
            default=Role.USER,  # Default to standard user
            nullable=False,
        ),
        description="The user's role, used for role-based access control (RBAC).",
    )
    is_active: bool = Field(
        default=True,  # Active by default
        description="Indicates if the user's account is active. Inactive users cannot log in.",
    )
    email_confirmed: bool = Field(
        default_factory=lambda: True,  # Default to confirmed, will be overridden in __init__
        description="Indicates if the user's email has been confirmed.",
    )
    created_at: datetime = Field(
        sa_column=Column(
            DateTime,  # Explicit DateTime type for Alembic
            server_default=text("CURRENT_TIMESTAMP"),  # Database timestamp
            nullable=False,
        ),
        description="The timestamp of when the user account was created.",
    )
    updated_at: Optional[datetime] = Field(
        sa_column=Column(
            DateTime,  # Explicit DateTime type for Alembic
            server_onupdate=text("CURRENT_TIMESTAMP"),  # Update on modification
            nullable=True,
        ),
        description="The timestamp of the last update to the user's record.",
    )
    password_reset_token: Optional[str] = Field(
        default=None,
        max_length=64,  # 32 bytes hex encoded = 64 characters
        description="A secure token for verifying a password reset request.",
    )
    password_reset_token_expires_at: Optional[datetime] = Field(
        sa_column=Column(
            DateTime,  # Explicit DateTime type for Alembic
            nullable=True,
        ),
        default=None,
        description="The expiration timestamp for the password reset token.",
    )
    email_confirmation_token: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Token used for confirming user email address.",
    )

    __table_args__ = (
        Index("ix_users_username_lower", text("lower(username)")),  # Case-insensitive index
        Index("ix_users_email_lower", text("lower(email)")),  # Case-insensitive index
        {"extend_existing": True},
    )

    def __init__(self, **data):
        """Initialize user with proper email confirmation setting."""
        super().__init__(**data)
        # Set email_confirmed based on settings (lazy import to avoid circular dependency)
        if not hasattr(self, '_email_confirmed_set'):
            try:
                from src.core.config.settings import settings
                self.email_confirmed = not settings.EMAIL_CONFIRMATION_ENABLED
            except ImportError:
                # Fallback if settings not available
                self.email_confirmed = True
            self._email_confirmed_set = True

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        """Validates and normalizes the username.

        Ensures the username contains only alphanumeric characters, underscores,
        or hyphens, and converts it to lowercase to enforce case-insensitivity.

        Raises:
            ValueError: If the username contains invalid characters.
        """
        if not value.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username can only contain alphanumeric characters, underscores, or hyphens")
        return value.lower()

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: EmailStr) -> str:
        """Normalizes the email address to lowercase.

        This ensures that email addresses are stored and compared in a
        case-insensitive manner, preventing duplicate accounts with different
        casing.
        """
        return value.lower()

    def verify_password(self, password: str) -> bool:
        """Verify a password against the user's hashed password.

        This method uses bcrypt to securely compare the provided password
        against the stored hash, implementing constant-time comparison to
        prevent timing attacks.

        Args:
            password: The plain text password to verify.

        Returns:
            bool: True if the password matches, False otherwise.

        Note:
            This method implements security best practices:
            - Uses bcrypt for secure password hashing
            - Implements constant-time comparison
            - Handles missing passwords gracefully
            - Provides clear return values
        """
        if not self.hashed_password:
            return False

        try:
            from passlib.context import CryptContext

            # Create password context with bcrypt
            pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
            return pwd_context.verify(password, self.hashed_password)
        except Exception:
            # Log the error but don't expose details
            return False

    def set_password(self, password: str) -> None:
        """Set a new password for the user.

        This method securely hashes the provided password using bcrypt
        and stores the hash in the user's record.

        Args:
            password: The plain text password to hash and store.

        Note:
            This method implements security best practices:
            - Uses bcrypt for secure password hashing
            - Configurable work factor for security vs performance
            - Handles password updates securely
            - Provides clear error handling
        """
        from passlib.context import CryptContext
        from src.core.config.settings import BCRYPT_WORK_FACTOR

        # Create password context with bcrypt
        pwd_context = CryptContext(
            schemes=["bcrypt"], 
            deprecated="auto", 
            bcrypt__rounds=BCRYPT_WORK_FACTOR
        )
        
        # Hash the password and store the hash
        self.hashed_password = pwd_context.hash(password)

    def __repr__(self) -> str:
        """Return a string representation of the user."""
        return f"User(id={self.id}, username='{self.username}', email='{self.email}', role={self.role})"
