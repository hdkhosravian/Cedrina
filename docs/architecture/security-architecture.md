# Security Architecture

This document describes the comprehensive security architecture implemented in Cedrina, focusing on defense-in-depth, threat detection, and enterprise-grade security controls.

## 🎯 Security Philosophy

Cedrina implements a **defense-in-depth** security approach with multiple layers of protection:

- **Zero Trust**: Verify every request and user
- **Security by Design**: Security built into every component
- **Privacy by Default**: PII protection and data minimization
- **Threat Detection**: Real-time security monitoring and response
- **Compliance Ready**: Audit trails and regulatory compliance

## 🏗️ Security Layers

### Layer 1: Input Validation & Sanitization
**Purpose**: Prevent malicious input and data corruption.

**Components**:
- **Pydantic Validation**: Type-safe input validation with custom validators
- **Input Sanitization**: XSS prevention and output encoding
- **SQL Injection Prevention**: Parameterized queries and input validation
- **Rate Limiting**: Abuse prevention and DDoS mitigation

**Implementation**:
```python
class Email:
    """Immutable email address with comprehensive validation."""
    
    def __post_init__(self):
        """Performs validation and normalization after initialization."""
        normalized_value = self.value.strip().lower()
        object.__setattr__(self, "value", normalized_value)
        
        self._validate_length(normalized_value)
        self._validate_format(normalized_value)
        self._validate_domain(normalized_value)
```

### Layer 2: Authentication & Authorization
**Purpose**: Verify user identity and control access to resources.

**Components**:
- **Multi-Factor Authentication**: Support for MFA implementation
- **JWT Token Validation**: RS256 algorithm with proper key management
- **Role-Based Access Control (RBAC)**: Casbin-based policy enforcement
- **Attribute-Based Access Control (ABAC)**: Dynamic access control
- **Token Family Security**: Session correlation and threat detection

**Implementation**:
```python
class JWTService(ITokenService, BaseInfrastructureService):
    """Infrastructure implementation of JWT token operations."""
    
    async def create_access_token(self, user: User, family_id: Optional[str] = None) -> AccessToken:
        """Creates a new JWT access token for a user."""
        payload = {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "iss": settings.JWT_ISSUER,
            "aud": settings.JWT_AUDIENCE,
            "exp": int(exp_time.timestamp()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "jti": jti
        }
        
        if family_id:
            payload["family_id"] = family_id
        
        token_string = jwt.encode(
            payload,
            settings.JWT_PRIVATE_KEY.get_secret_value(),
            algorithm="RS256"
        )
```

### Layer 3: Rate Limiting & Abuse Prevention
**Purpose**: Prevent abuse and ensure fair resource usage.

**Components**:
- **Advanced Rate Limiting**: Multiple algorithms (token bucket, sliding window, fixed window)
- **Hierarchical Quotas**: Global, user, endpoint, and tier-based limits
- **Dynamic Configuration**: Environment-based rate limiting policies
- **Bypass Detection**: IP spoofing and header manipulation detection

**Implementation**:
```python
@dataclass(frozen=True, slots=True)
class RateLimitKey:
    """Immutable value object representing a unique rate limiting context."""
    
    user_id: Optional[str] = None
    endpoint: Optional[str] = None
    client_ip: Optional[str] = None
    user_tier: Optional[str] = None
    custom_context: Optional[str] = None
    
    @property
    def hierarchical_keys(self) -> list[str]:
        """Generate hierarchical keys for multi-level rate limiting."""
        keys = []
        keys.append(self.composite_key)
        
        if self.user_id and self.endpoint:
            user_endpoint_key = RateLimitKey(user_id=self.user_id, endpoint=self.endpoint)
            keys.append(user_endpoint_key.composite_key)
        
        if self.user_id:
            user_key = RateLimitKey(user_id=self.user_id)
            keys.append(user_key.composite_key)
        
        return keys
```

### Layer 4: Data Protection
**Purpose**: Protect sensitive data and ensure data integrity.

**Components**:
- **AES-256-GCM Encryption**: Field-level encryption for sensitive data
- **Bcrypt Password Hashing**: Configurable work factor for password security
- **Token Family Security**: Session correlation and threat detection
- **Secure Session Management**: Inactivity timeouts and session revocation

**Implementation**:
```python
class FieldEncryptionService:
    """Service for encrypting sensitive fields in the database."""
    
    def __init__(self, encryption_key: str):
        self.encryption_key = encryption_key.encode()
    
    def encrypt_field(self, plaintext: str) -> str:
        """Encrypt a field using AES-256-GCM."""
        if not plaintext:
            return plaintext
        
        # Generate a random nonce
        nonce = os.urandom(12)
        
        # Create cipher
        cipher = AES.new(self.encryption_key, AES.MODE_GCM, nonce=nonce)
        
        # Encrypt the data
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
        
        # Combine nonce, ciphertext, and tag
        encrypted_data = nonce + ciphertext + tag
        
        # Return as base64 encoded string
        return base64.b64encode(encrypted_data).decode()
```

### Layer 5: Audit & Monitoring
**Purpose**: Comprehensive logging and threat detection.

**Components**:
- **Structured Security Events**: SIEM-compatible event format
- **Comprehensive Audit Logging**: Correlation IDs and privacy compliance
- **Real-Time Threat Detection**: Security event correlation and analysis
- **Privacy-Compliant Data Handling**: PII masking and data protection

**Implementation**:
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
    checksum: Optional[str] = None
    
    def to_siem_format(self) -> Dict[str, Any]:
        """Convert event to SIEM-compatible format."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_id": self.event_id,
            "category": self.category.value,
            "severity": self._severity_to_numeric(),
            "title": self.title,
            "description": self.description,
            "outcome": self.outcome,
            "actor_id": self.actor_id,
            "risk_score": self.risk_score,
            "checksum": self.checksum
        }
```

## 🔐 Advanced Security Features

### Token Family Security
**Purpose**: Group related tokens for security correlation and threat detection.

**Features**:
- **Database-Only Storage**: Eliminates Redis complexity
- **Token Family Correlation**: Groups related tokens for analysis
- **ACID Transactions**: Ensures consistency and data integrity
- **Advanced Threat Detection**: Real-time security monitoring

**Implementation**:
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

### Rate Limiting Architecture
**Purpose**: Prevent abuse and ensure fair resource usage.

**Features**:
- **Multi-Algorithm Support**: Token bucket, sliding window, fixed window
- **Hierarchical Quotas**: Global, user, endpoint, and tier-based limits
- **Dynamic Configuration**: Environment-based rate limiting policies
- **Bypass Detection**: IP spoofing and header manipulation detection

**Implementation**:
```python
def _get_secure_client_ip(request: Request) -> str:
    """Get the client IP address securely, preventing IP spoofing attacks."""
    real_client_ip = request.client.host if request.client else "unknown"
    
    forwarded_headers = [
        "X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
        "X-Remote-IP", "X-Remote-Addr", "CF-Connecting-IP", "True-Client-IP"
    ]
    
    suspicious_headers = []
    for header in forwarded_headers:
        if header in request.headers:
            forwarded_ip = request.headers[header]
            if forwarded_ip != real_client_ip:
                suspicious_headers.append(f"{header}: {forwarded_ip}")
    
    if suspicious_headers:
        logger.warning(
            f"Potential IP spoofing attempt detected. "
            f"Real IP: {real_client_ip}, Forwarded headers: {suspicious_headers}"
        )
    
    return real_client_ip
```

### Security Event System
**Purpose**: Comprehensive security monitoring and threat detection.

**Features**:
- **Structured Events**: SIEM-compatible event format
- **Threat Intelligence**: Risk scoring and attack pattern detection
- **Privacy Compliance**: PII masking and data protection
- **Audit Trails**: Comprehensive logging for compliance

**Implementation**:
```python
class SecurityEventLogger:
    """Logger for structured security events."""
    
    def __init__(self):
        self.logger = structlog.get_logger("security_events")
    
    def log_authentication_success(
        self,
        username_masked: str,
        correlation_id: str,
        client_ip_masked: str,
        user_agent_sanitized: str
    ) -> None:
        """Log successful authentication event."""
        event = StructuredEventBuilder().authentication_event(
            event_type="login",
            outcome="success",
            username_masked=username_masked
        ).with_request_context(
            correlation_id=correlation_id,
            client_ip_masked=client_ip_masked,
            user_agent_sanitized=user_agent_sanitized
        ).build()
        
        self.logger.info("Authentication success", **event.to_siem_format())
```

## 🛡️ Threat Detection

### Brute Force Detection
**Purpose**: Detect and prevent brute force attacks.

**Features**:
- **Rate Limiting**: Automatic rate limiting for failed attempts
- **Account Lockout**: Temporary account lockout after multiple failures
- **IP Blocking**: Block suspicious IP addresses
- **Alert Generation**: Real-time alerts for security incidents

### Session Hijacking Prevention
**Purpose**: Prevent session hijacking and token theft.

**Features**:
- **Token Family Correlation**: Group related tokens for analysis
- **Session Inactivity Timeouts**: Automatic session expiration
- **IP Address Validation**: Validate session IP addresses
- **User Agent Validation**: Validate session user agents

### Data Exfiltration Prevention
**Purpose**: Prevent unauthorized data access and exfiltration.

**Features**:
- **Field-Level Encryption**: Encrypt sensitive data fields
- **Access Logging**: Log all data access attempts
- **Data Masking**: Mask sensitive data in logs
- **Audit Trails**: Comprehensive audit logging

## 🔍 Security Monitoring

### Real-Time Monitoring
**Purpose**: Monitor system security in real-time.

**Components**:
- **Security Event Correlation**: Correlate events for threat detection
- **Anomaly Detection**: Detect unusual patterns and behaviors
- **Alert Generation**: Generate alerts for security incidents
- **Response Automation**: Automated response to security threats

### Compliance Monitoring
**Purpose**: Ensure regulatory compliance and audit requirements.

**Components**:
- **Audit Logging**: Comprehensive audit trails
- **Data Retention**: Proper data retention policies
- **Privacy Protection**: PII handling and data protection
- **Compliance Reporting**: Generate compliance reports

## 📊 Security Metrics

### Threat Metrics
- **Failed Authentication Attempts**: Number of failed login attempts
- **Rate Limit Violations**: Number of rate limit violations
- **Security Incidents**: Number of security incidents detected
- **Response Times**: Time to detect and respond to threats

### Compliance Metrics
- **Audit Trail Completeness**: Percentage of events logged
- **Data Protection**: Encryption coverage and effectiveness
- **Privacy Compliance**: PII handling compliance
- **Regulatory Compliance**: Compliance with relevant regulations

## 🚀 Security Best Practices

### Authentication Best Practices
1. **Strong Password Policies**: Enforce strong password requirements
2. **Multi-Factor Authentication**: Implement MFA where possible
3. **Session Management**: Proper session lifecycle management
4. **Token Security**: Secure token generation and validation

### Authorization Best Practices
1. **Principle of Least Privilege**: Grant minimum necessary permissions
2. **Role-Based Access Control**: Implement RBAC for access control
3. **Attribute-Based Access Control**: Use ABAC for dynamic access control
4. **Regular Access Reviews**: Regular review of user permissions

### Data Protection Best Practices
1. **Encryption at Rest**: Encrypt sensitive data in storage
2. **Encryption in Transit**: Use TLS for data in transit
3. **Data Minimization**: Collect only necessary data
4. **Privacy by Design**: Build privacy into system design

### Monitoring Best Practices
1. **Comprehensive Logging**: Log all security-relevant events
2. **Real-Time Monitoring**: Monitor security events in real-time
3. **Alert Management**: Proper alert configuration and management
4. **Incident Response**: Plan and practice incident response

## 🎯 Benefits

### Security Benefits
- **Defense in Depth**: Multiple layers of security protection
- **Threat Detection**: Real-time threat detection and response
- **Compliance Ready**: Built-in compliance and audit capabilities
- **Privacy Protection**: Comprehensive PII protection

### Operational Benefits
- **Monitoring**: Comprehensive security monitoring
- **Alerting**: Real-time security alerts
- **Response**: Automated and manual response capabilities
- **Reporting**: Security metrics and compliance reporting

### Business Benefits
- **Risk Reduction**: Reduced security risks and incidents
- **Compliance**: Regulatory compliance and audit readiness
- **Trust**: Enhanced customer and stakeholder trust
- **Cost Savings**: Reduced security incident costs

---

*Last updated: January 2025* 