# Token Management System

Cedrina implements an advanced token management system with JWT tokens, token family security, and database-only storage. This system provides enterprise-grade security with reuse detection, family-wide revocation, and comprehensive audit logging.

## 🏗️ Architecture Overview

### **Core Components**
- **JWT Token Service**: RS256-signed access and refresh tokens
- **Token Family Security**: Advanced reuse detection and family-wide revocation
- **Database-Only Storage**: Eliminates Redis complexity for token management
- **Session Management**: Database-backed session tracking with activity monitoring
- **Audit Logging**: Comprehensive security event logging for compliance

### **Token Flow**
```
Login → Token Generation → Family Creation → Database Storage
    ↓           ↓              ↓              ↓
User Auth → JWT Creation → Family Grouping → Secure Storage
```

## 🔐 JWT Token System

### **Token Types**
- **Access Tokens**: Short-lived (15 minutes) for API access
- **Refresh Tokens**: Long-lived (7 days) for token renewal
- **Token Families**: Groups related tokens for security correlation

### **Token Structure**
```json
{
  "sub": "user_id",
  "iss": "https://api.cedrina.com",
  "aud": "cedrina:api:v1",
  "exp": 1640995200,
  "iat": 1640991600,
  "jti": "unique_token_id",
  "family_id": "token_family_uuid",
  "session_id": "session_uuid"
}
```

### **Security Features**
- **RS256 Signing**: Asymmetric key signing for token integrity
- **Token Family Security**: Groups tokens for reuse detection
- **Database Storage**: Secure storage with encryption
- **Audit Trail**: Complete token lifecycle logging

## 🛡️ Token Family Security

### **Family Concept**
Token families group related tokens (access + refresh) for security correlation and threat detection.

### **Family Structure**
```python
class TokenFamily:
    """Token family for security correlation."""
    
    id: UUID  # Unique family identifier
    user_id: int  # Associated user
    created_at: datetime  # Family creation time
    is_active: bool  # Family status
    last_used: datetime  # Last activity timestamp
    ip_address: str  # Creation IP address
    user_agent: str  # Creation user agent
```

### **Security Benefits**
- **Reuse Detection**: Identifies token reuse across families
- **Family-wide Revocation**: Compromises entire families on security violations
- **Threat Pattern Analysis**: Detects sophisticated attack patterns
- **Audit Correlation**: Links related security events

### **Family Lifecycle**
```
1. Login → Create Family → Generate Tokens
2. Token Usage → Update Last Used → Log Activity
3. Security Violation → Revoke Family → Log Incident
4. Token Refresh → Validate Family → Generate New Tokens
```

## 🗄️ Database-Only Storage

### **Storage Strategy**
- **No Redis Dependency**: Eliminates Redis complexity for token management
- **ACID Transactions**: Ensures consistency and data integrity
- **Encrypted Storage**: Sensitive data encrypted at rest
- **Performance Optimized**: Sub-millisecond response times

### **Database Tables**

#### **Token Families Table**
```sql
CREATE TABLE token_families (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE,
    last_used TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    created_by TEXT DEFAULT 'system'
);
```

#### **Sessions Table**
```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id INTEGER NOT NULL REFERENCES users(id),
    token_family_id UUID REFERENCES token_families(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    ip_address INET,
    user_agent TEXT
);
```

## 🔄 Token Operations

### **Token Generation**
```python
async def create_token_pair(
    token_service: ITokenService,
    user: User,
    correlation_id: str
) -> TokenPair:
    """Create access and refresh token pair."""
    
    # Generate token family
    family = await token_service.create_token_family(user)
    
    # Generate access token
    access_token = await token_service.create_access_token(
        user, family.id, correlation_id
    )
    
    # Generate refresh token
    refresh_token = await token_service.create_refresh_token(
        user, family.id, correlation_id
    )
    
    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="Bearer",
        expires_in=900  # 15 minutes
    )
```

### **Token Validation**
```python
async def validate_token(
    token_service: ITokenService,
    token: str,
    token_type: str
) -> User:
    """Validate JWT token and return user."""
    
    # Decode and validate token
    payload = await token_service.decode_token(token, token_type)
    
    # Verify token family is active
    family = await token_service.get_token_family(payload.family_id)
    if not family.is_active:
        raise TokenFamilyRevokedError("Token family has been revoked")
    
    # Update last used timestamp
    await token_service.update_family_activity(family.id)
    
    return await token_service.get_user_from_payload(payload)
```

### **Token Refresh**
```python
async def refresh_tokens(
    token_service: ITokenService,
    refresh_token: str,
    correlation_id: str
) -> TokenPair:
    """Refresh access token using refresh token."""
    
    # Validate refresh token
    payload = await token_service.decode_token(refresh_token, "refresh")
    
    # Verify token family
    family = await token_service.get_token_family(payload.family_id)
    if not family.is_active:
        raise TokenFamilyRevokedError("Token family has been revoked")
    
    # Generate new access token
    new_access_token = await token_service.create_access_token(
        payload.user_id, family.id, correlation_id
    )
    
    return TokenPair(
        access_token=new_access_token,
        refresh_token=refresh_token,  # Keep existing refresh token
        token_type="Bearer",
        expires_in=900
    )
```

## 🚨 Security Features

### **Reuse Detection**
```python
async def detect_token_reuse(
    token_service: ITokenService,
    token: str,
    family_id: UUID
) -> bool:
    """Detect token reuse across families."""
    
    # Check if token has been used before
    if await token_service.is_token_used(token):
        # Revoke entire family
        await token_service.revoke_token_family(family_id)
        
        # Log security incident
        await log_security_incident(
            "token_reuse_detected",
            family_id=family_id,
            token_hash=hash_token(token)
        )
        
        return True
    
    return False
```

### **Family-wide Revocation**
```python
async def revoke_token_family(
    token_service: ITokenService,
    family_id: UUID,
    reason: str
) -> None:
    """Revoke entire token family."""
    
    # Mark family as inactive
    await token_service.deactivate_family(family_id)
    
    # Invalidate all associated sessions
    await token_service.invalidate_family_sessions(family_id)
    
    # Log revocation
    await log_security_incident(
        "token_family_revoked",
        family_id=family_id,
        reason=reason
    )
```

### **Session Management**
```python
async def create_session(
    token_service: ITokenService,
    user: User,
    family_id: UUID,
    ip_address: str,
    user_agent: str
) -> Session:
    """Create new user session."""
    
    session = await token_service.create_session(
        user_id=user.id,
        family_id=family_id,
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    # Log session creation
    await log_security_event(
        "session_created",
        user_id=user.id,
        session_id=session.id,
        ip_address=ip_address
    )
    
    return session
```

## 📋 API Endpoints

### **Token Refresh**
```http
POST /api/v1/auth/refresh
Authorization: Bearer <access_token>
X-Refresh-Token: <refresh_token>
Content-Type: application/json

{}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

### **Logout**
```http
POST /api/v1/auth/logout
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

## 🔧 Configuration

### **JWT Settings**
```python
# JWT Configuration
JWT_PRIVATE_KEY_PATH = "/path/to/private.pem"
JWT_PUBLIC_KEY_PATH = "/path/to/public.pem"
JWT_ISSUER = "https://api.cedrina.com"
JWT_AUDIENCE = "cedrina:api:v1"

# Token Expiration
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Security Settings
TOKEN_FAMILY_ENABLED = True
REUSE_DETECTION_ENABLED = True
AUDIT_LOGGING_ENABLED = True
```

### **Database Settings**
```python
# Session Management
SESSION_INACTIVITY_TIMEOUT_MINUTES = 30
MAX_CONCURRENT_SESSIONS_PER_USER = 5

# Token Family Settings
MAX_TOKEN_FAMILIES_PER_USER = 10
FAMILY_CLEANUP_INTERVAL_HOURS = 24
```

## 🧪 Testing

### **Unit Tests**
```python
def test_token_generation():
    """Test JWT token generation."""
    
def test_token_validation():
    """Test token validation and decoding."""
    
def test_token_family_security():
    """Test token family security features."""
    
def test_reuse_detection():
    """Test token reuse detection."""
```

### **Integration Tests**
```python
def test_token_refresh_flow():
    """Test complete token refresh workflow."""
    
def test_family_revocation():
    """Test family-wide token revocation."""
    
def test_session_management():
    """Test session creation and management."""
```

## 📊 Monitoring

### **Token Metrics**
- **Token Generation**: Tokens created per time period
- **Token Validation**: Validation success/failure rates
- **Family Operations**: Family creation, revocation, cleanup
- **Session Activity**: Active sessions and activity patterns

### **Security Monitoring**
- **Reuse Attempts**: Token reuse detection events
- **Family Revocations**: Security-triggered revocations
- **Session Anomalies**: Unusual session patterns
- **Access Patterns**: Token usage patterns and trends

## 🚀 Best Practices

### **Token Security**
- **Short-lived Access Tokens**: 15-minute expiration for access tokens
- **Secure Refresh Tokens**: Long-lived but revocable refresh tokens
- **Family Grouping**: Group related tokens for security correlation
- **Audit Logging**: Log all token operations for compliance

### **Session Management**
- **Database Storage**: Store sessions in database for persistence
- **Activity Tracking**: Track session activity and last used times
- **Concurrent Limits**: Limit concurrent sessions per user
- **Inactivity Timeout**: Automatically expire inactive sessions

### **Security Monitoring**
- **Reuse Detection**: Monitor for token reuse attempts
- **Pattern Analysis**: Analyze token usage patterns
- **Incident Response**: Automated response to security incidents
- **Compliance Reporting**: Generate compliance reports

## 🔗 Related Documentation

- [Authentication System](../authentication/README.md) - User authentication flows
- [Authorization System](../authorization/README.md) - Access control and permissions
- [Rate Limiting](../rate-limiting/README.md) - API rate limiting and protection
- [Security Overview](../../security/overview.md) - Overall security architecture 