# Domain Design

This document describes the Domain-Driven Design (DDD) implementation in Cedrina, focusing on the core domain concepts, bounded contexts, and business rules.

## 🎯 Domain Overview

Cedrina's domain centers around **authentication and authorization** with a focus on security, user management, and session control. The domain is designed to handle complex security scenarios while maintaining clean separation of concerns.

## 🏗️ Bounded Contexts

### Authentication Context
**Purpose**: Manages user authentication, session creation, and security validation.

**Core Concepts**:
- **User**: The primary entity representing a system user
- **Session**: Active user sessions with security context
- **Token Family**: Grouped tokens for security correlation
- **Authentication Event**: Domain events for audit trails

**Key Business Rules**:
- Users must have unique usernames and emails
- Passwords must meet security policy requirements
- Sessions have inactivity timeouts
- Token families provide security correlation

### Authorization Context
**Purpose**: Controls access to resources and enforces security policies.

**Core Concepts**:
- **Role**: User roles defining permission levels
- **Policy**: Access control policies (RBAC/ABAC)
- **Permission**: Granular access permissions
- **Security Event**: Authorization audit events

**Key Business Rules**:
- Role-based access control (RBAC)
- Attribute-based access control (ABAC)
- Time-based access restrictions
- Department/location-based access

### Rate Limiting Context
**Purpose**: Prevents abuse and ensures fair resource usage.

**Core Concepts**:
- **Rate Limit Policy**: Configuration for rate limiting
- **Rate Limit Result**: Outcome of rate limiting decisions
- **Rate Limit Request**: Input for rate limiting decisions
- **Quota**: Usage limits and allowances

**Key Business Rules**:
- Multiple rate limiting algorithms supported
- Hierarchical quotas (global, user, endpoint)
- Dynamic configuration based on environment
- Bypass detection for security threats

## 🏛️ Domain Entities

### User Entity
```python
class User(SQLModel, table=True):
    """Represents a User entity and acts as an Aggregate Root."""
    
    id: Optional[int] = Field(primary_key=True)
    username: str = Field(unique=True, index=True)
    email: EmailStr = Field(unique=True, index=True)
    hashed_password: Optional[str] = Field()
    role: Role = Field(default=Role.USER)
    is_active: bool = Field(default=True)
    email_confirmed: bool = Field(default_factory=lambda: True)
    created_at: datetime = Field()
    updated_at: Optional[datetime] = Field()
    password_reset_token: Optional[str] = Field()
    password_reset_token_expires_at: Optional[datetime] = Field()
    email_confirmation_token: Optional[str] = Field()
```

**Business Rules**:
- Username must be 3-50 characters, alphanumeric with underscores/hyphens
- Email must be unique and properly formatted
- Password must meet security policy requirements
- Users are active by default
- Email confirmation can be enabled/disabled

### Session Entity
```python
class Session(SQLModel, table=True):
    """Represents a user session with security context."""
    
    id: Optional[int] = Field(primary_key=True)
    user_id: int = Field(foreign_key="users.id")
    session_id: str = Field(unique=True, index=True)
    ip_address: str = Field()
    user_agent: str = Field()
    created_at: datetime = Field()
    last_activity: datetime = Field()
    is_active: bool = Field(default=True)
```

**Business Rules**:
- Sessions have unique identifiers
- Sessions track IP address and user agent
- Sessions have inactivity timeouts
- Sessions can be revoked for security

### Token Family Entity
```python
class TokenFamily(SQLModel, table=True):
    """Represents a family of related tokens for security correlation."""
    
    id: Optional[int] = Field(primary_key=True)
    user_id: int = Field(foreign_key="users.id")
    family_id: str = Field(unique=True, index=True)
    token_hash: str = Field()
    created_at: datetime = Field()
    expires_at: datetime = Field()
    is_revoked: bool = Field(default=False)
```

**Business Rules**:
- Token families group related tokens
- Tokens have expiration times
- Tokens can be revoked for security
- Token families enable security correlation

## 💎 Value Objects

### Email Value Object
```python
@dataclass(frozen=True, slots=True)
class Email:
    """Immutable email address with validation."""
    
    value: str
    MAX_LENGTH: ClassVar[int] = 254
    MIN_LENGTH: ClassVar[int] = 5
    EMAIL_PATTERN: ClassVar[re.Pattern] = re.compile(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    )
    BLOCKED_DOMAINS: ClassVar[set] = {
        "10minutemail.com", "tempmail.org", "guerrillamail.com"
    }
```

**Business Rules**:
- Email must be 5-254 characters
- Email must match RFC 5322 format
- Disposable email providers are blocked
- Email is normalized to lowercase

### Password Value Object
```python
@dataclass(frozen=True, slots=True)
class Password:
    """Immutable password with security validation."""
    
    value: str
    MIN_LENGTH: ClassVar[int] = 8
    MAX_LENGTH: ClassVar[int] = 128
    REQUIRE_UPPERCASE: ClassVar[bool] = True
    REQUIRE_LOWERCASE: ClassVar[bool] = True
    REQUIRE_DIGIT: ClassVar[bool] = True
    REQUIRE_SPECIAL_CHAR: ClassVar[bool] = True
```

**Business Rules**:
- Password must be 8-128 characters
- Must contain uppercase, lowercase, digit, and special character
- Password is validated against security policy
- Password is hashed using bcrypt

### Username Value Object
```python
@dataclass(frozen=True, slots=True)
class Username:
    """Immutable username with validation."""
    
    value: str
    MIN_LENGTH: ClassVar[int] = 3
    MAX_LENGTH: ClassVar[int] = 50
    USERNAME_PATTERN: ClassVar[re.Pattern] = re.compile(
        r"^[a-zA-Z0-9_-]+$"
    )
```

**Business Rules**:
- Username must be 3-50 characters
- Username must be alphanumeric with underscores/hyphens
- Username is normalized to lowercase
- Username must be unique

## 🔄 Domain Services

### Authentication Service
```python
class PasswordChangeService(IPasswordChangeService, BaseAuthenticationService):
    """Clean architecture password change service following DDD principles."""
    
    async def change_password(
        self,
        user_id: int,
        old_password: str,
        new_password: str,
        language: str = "en",
        client_ip: str = "",
        user_agent: str = "",
        correlation_id: str = "",
    ) -> None:
        """Change user password with comprehensive security validation."""
```

**Responsibilities**:
- Validates old password
- Enforces password policy
- Prevents password reuse
- Publishes domain events
- Provides audit trails

### Rate Limiting Service
```python
class RateLimitPolicy:
    """Entity representing a rate limiting policy with hierarchical quotas."""
    
    algorithm: RateLimitAlgorithm
    quotas: Dict[str, RateLimitQuota] = field(default_factory=dict)
    user_tiers: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    priority: int = 100
    enabled: bool = True
```

**Responsibilities**:
- Configures rate limiting policies
- Manages hierarchical quotas
- Supports multiple algorithms
- Provides bypass detection

## 📡 Domain Events

### Authentication Events
```python
@dataclass(frozen=True)
class UserLoggedInEvent(BaseDomainEvent, UserEventMixin, EmailEventMixin):
    """Domain event published when a user logs in successfully."""
    user_id: int
    email: Optional[str] = None

@dataclass(frozen=True)
class PasswordChangedEvent(BaseDomainEvent, UserEventMixin):
    """Domain event published when a user changes their password."""
    user_id: int

@dataclass(frozen=True)
class SessionCreatedEvent(BaseDomainEvent, UserEventMixin, SessionEventMixin, TokenEventMixin):
    """Domain event published when a session is created."""
    session_id: str
    user_id: int
    family_id: Optional[str] = None
```

### Security Events
```python
@dataclass(frozen=True)
class SecurityIncidentEvent(BaseDomainEvent, SecurityEventMixin, StringValidationMixin, UserEventMixin, TokenEventMixin):
    """Domain event published for general security incidents."""
    incident_type: str
    threat_level: SecurityThreatLevel
    description: str
    user_id: Optional[int] = None
    family_id: Optional[str] = None
    token_id: Optional[str] = None
```

## 🗄️ Repository Interfaces

### User Repository Interface
```python
class IUserRepository(ABC):
    """Interface defining the contract for user persistence operations."""
    
    @abstractmethod
    async def get_by_id(self, user_id: int) -> Optional[User]:
        """Retrieves a user by their unique identifier."""
        raise NotImplementedError
    
    @abstractmethod
    async def get_by_username(self, username: str) -> Optional[User]:
        """Retrieves a user by their username (case-insensitively)."""
        raise NotImplementedError
    
    @abstractmethod
    async def get_by_email(self, email: str) -> Optional[User]:
        """Retrieves a user by their email address (case-insensitively)."""
        raise NotImplementedError
    
    @abstractmethod
    async def save(self, user: User) -> User:
        """Persists a new user or updates an existing one."""
        raise NotImplementedError
```

## 🔐 Security Domain

### Security Context
```python
@dataclass
class SecurityContext:
    """Security context for domain operations."""
    
    client_ip: str
    user_agent: str
    correlation_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    risk_score: int = 0
    threat_indicators: List[str] = field(default_factory=list)
```

### Security Event System
```python
@dataclass(frozen=True)
class StructuredSecurityEvent:
    """Comprehensive structured security event for audit and monitoring."""
    
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    category: SecurityEventCategory = SecurityEventCategory.AUTHENTICATION
    severity: SecurityEventLevel = SecurityEventLevel.MEDIUM
    title: str = ""
    description: str = ""
    outcome: str = ""
    actor_id: Optional[str] = None
    risk_score: int = 0
    confidence_level: int = 100
```

## 🧪 Testing Strategy

### Domain Testing
- **Unit Tests**: Test domain entities, value objects, and business rules
- **Integration Tests**: Test domain services with repositories
- **Property-Based Tests**: Test invariants and edge cases
- **Security Tests**: Test security policies and threat detection

### Test Categories
- **Entity Tests**: Validate business rules and invariants
- **Value Object Tests**: Test validation and immutability
- **Domain Service Tests**: Test business logic and workflows
- **Event Tests**: Test domain event publishing and handling

## 📊 Domain Metrics

### Business Metrics
- User registration and authentication success rates
- Password change and reset completion rates
- Session creation and management metrics
- Security incident detection and response times

### Technical Metrics
- Domain service performance and response times
- Repository operation efficiency
- Event publishing and handling metrics
- Error rates and failure patterns

## 🎯 Benefits

### Maintainability
- **Clear Domain Boundaries**: Well-defined bounded contexts
- **Rich Domain Models**: Business logic encapsulated in entities
- **Immutable Value Objects**: Data integrity and thread safety
- **Domain Events**: Loose coupling and audit trails

### Testability
- **Isolated Domain Logic**: Pure business logic without infrastructure
- **Mockable Interfaces**: Repository and service interfaces
- **Comprehensive Testing**: Unit, integration, and property-based tests
- **Fast Test Execution**: Domain tests run in milliseconds

### Security
- **Domain-Driven Security**: Security rules in domain models
- **Event-Driven Auditing**: Comprehensive audit trails
- **Threat Detection**: Real-time security monitoring
- **Privacy Compliance**: PII handling and data protection

### Scalability
- **Event-Driven Architecture**: Loose coupling for scalability
- **Repository Pattern**: Abstract data access for flexibility
- **Value Objects**: Immutable data for concurrency
- **Domain Services**: Stateless business logic

---

*Last updated: January 2025* 