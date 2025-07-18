# Rate Limiting System

Cedrina implements a sophisticated rate limiting system with multiple algorithms, bypass detection, and abuse prevention. This system protects against brute force attacks, DoS attempts, and ensures fair usage across all API endpoints.

## 🏗️ Architecture Overview

### **Core Components**
- **Multiple Algorithms**: Fixed window, sliding window, and token bucket algorithms
- **Bypass Detection**: Advanced detection of rate limiting bypass attempts
- **Redis Integration**: Optional Redis backend for distributed rate limiting
- **Configurable Limits**: Per-endpoint and per-user rate limiting rules
- **Audit Logging**: Comprehensive logging of rate limiting events

### **Rate Limiting Flow**
```
Request → Rate Limiter → Algorithm Check → Decision
    ↓           ↓              ↓              ↓
API Call → Limit Check → Window/Token → Allow/Block
```

## 🔧 Rate Limiting Algorithms

### **1. Fixed Window Algorithm**
- **Description**: Simple time-based window with fixed boundaries
- **Use Case**: Basic rate limiting for simple scenarios
- **Pros**: Simple implementation, low memory usage
- **Cons**: Burst traffic at window boundaries

```python
class FixedWindowRateLimiter:
    """Fixed window rate limiter implementation."""
    
    def is_allowed(self, key: str, limit: int, window: int) -> bool:
        """Check if request is allowed within fixed window."""
        current_time = int(time.time())
        window_start = current_time - (current_time % window)
        
        # Get current count for window
        count = self.get_count(key, window_start)
        
        if count < limit:
            self.increment_count(key, window_start)
            return True
        
        return False
```

### **2. Sliding Window Algorithm**
- **Description**: Smooth sliding window with weighted calculations
- **Use Case**: More accurate rate limiting for production use
- **Pros**: Smooth traffic distribution, accurate counting
- **Cons**: Higher memory usage, more complex

```python
class SlidingWindowRateLimiter:
    """Sliding window rate limiter implementation."""
    
    def is_allowed(self, key: str, limit: int, window: int) -> bool:
        """Check if request is allowed within sliding window."""
        current_time = time.time()
        
        # Calculate weighted count from previous window
        previous_window = current_time - window
        previous_count = self.get_count(key, previous_window)
        
        # Calculate current window weight
        weight = (current_time - previous_window) / window
        
        # Calculate total weighted count
        total_count = previous_count * weight + self.get_current_count(key)
        
        if total_count < limit:
            self.increment_count(key, current_time)
            return True
        
        return False
```

### **3. Token Bucket Algorithm**
- **Description**: Token-based algorithm with burst allowance
- **Use Case**: APIs that allow burst traffic with sustained limits
- **Pros**: Allows bursts, smooth traffic handling
- **Cons**: More complex implementation

```python
class TokenBucketRateLimiter:
    """Token bucket rate limiter implementation."""
    
    def is_allowed(self, key: str, capacity: int, rate: float) -> bool:
        """Check if request is allowed using token bucket."""
        current_time = time.time()
        
        # Get bucket state
        bucket = self.get_bucket(key)
        
        # Calculate tokens to add
        tokens_to_add = (current_time - bucket.last_refill) * rate
        bucket.tokens = min(capacity, bucket.tokens + tokens_to_add)
        bucket.last_refill = current_time
        
        if bucket.tokens >= 1:
            bucket.tokens -= 1
            self.update_bucket(key, bucket)
            return True
        
        return False
```

## 🛡️ Bypass Detection

### **Detection Methods**
- **IP Rotation**: Detect rapid IP address changes
- **User Agent Spoofing**: Identify fake user agents
- **Header Manipulation**: Detect modified rate limit headers
- **Timing Analysis**: Analyze request timing patterns

### **Bypass Detection Implementation**
```python
class BypassDetector:
    """Detect rate limiting bypass attempts."""
    
    def detect_bypass(self, request: Request) -> BypassAttempt:
        """Detect bypass attempts in request."""
        
        # Check IP rotation
        if self.detect_ip_rotation(request):
            return BypassAttempt.IP_ROTATION
            
        # Check user agent spoofing
        if self.detect_user_agent_spoofing(request):
            return BypassAttempt.USER_AGENT_SPOOFING
            
        # Check header manipulation
        if self.detect_header_manipulation(request):
            return BypassAttempt.HEADER_MANIPULATION
            
        # Check timing patterns
        if self.detect_timing_patterns(request):
            return BypassAttempt.TIMING_ANOMALY
            
        return BypassAttempt.NONE
```

## 📋 Configuration

### **Rate Limiting Rules**
```python
# Authentication endpoints
AUTH_LOGIN_LIMIT = "5/minute"
AUTH_REGISTER_LIMIT = "3/hour"
AUTH_FORGOT_PASSWORD_LIMIT = "3/hour"
AUTH_RESET_PASSWORD_LIMIT = "5/hour"

# Admin endpoints
ADMIN_POLICY_ADD_LIMIT = "50/minute"
ADMIN_POLICY_REMOVE_LIMIT = "50/minute"
ADMIN_POLICY_LIST_LIMIT = "100/minute"

# General API endpoints
API_GENERAL_LIMIT = "1000/hour"
API_BURST_LIMIT = "100/minute"

# Bypass detection
BYPASS_DETECTION_ENABLED = True
IP_ROTATION_THRESHOLD = 5  # IPs per minute
USER_AGENT_SPOOFING_ENABLED = True
TIMING_ANALYSIS_ENABLED = True
```

### **Redis Configuration**
```python
# Redis settings (optional)
REDIS_URL = "redis://localhost:6379/0"
REDIS_RATE_LIMITING_ENABLED = True
REDIS_KEY_PREFIX = "rate_limit:"
REDIS_EXPIRY_SECONDS = 3600
```

## 🎨 Usage Examples

### **Basic Rate Limiting**
```python
from src.core.rate_limiting.ratelimiter import get_limiter

limiter = get_limiter()

@router.post("/login")
@limiter.limit("5/minute")
async def login(request: Request):
    """Login endpoint with rate limiting."""
    # Endpoint implementation
```

### **Custom Rate Limiting**
```python
@router.post("/register")
@limiter.limit("3/hour", key_func=lambda r: f"register:{r.client.host}")
async def register(request: Request):
    """Registration with custom key function."""
    # Endpoint implementation
```

### **Bypass Detection**
```python
@router.post("/sensitive-endpoint")
@limiter.limit("10/minute")
@limiter.detect_bypass()
async def sensitive_endpoint(request: Request):
    """Endpoint with bypass detection."""
    # Endpoint implementation
```

## 📊 Monitoring

### **Rate Limiting Metrics**
- **Request Counts**: Total requests per endpoint
- **Blocked Requests**: Rate-limited requests per endpoint
- **Bypass Attempts**: Detected bypass attempts
- **Algorithm Performance**: Response times for each algorithm

### **Security Monitoring**
- **IP Rotation**: Rapid IP address changes
- **User Agent Anomalies**: Suspicious user agent patterns
- **Header Manipulation**: Modified rate limit headers
- **Timing Patterns**: Unusual request timing

## 🧪 Testing

### **Unit Tests**
```python
def test_fixed_window_limiter():
    """Test fixed window rate limiting."""
    
def test_sliding_window_limiter():
    """Test sliding window rate limiting."""
    
def test_token_bucket_limiter():
    """Test token bucket rate limiting."""
    
def test_bypass_detection():
    """Test bypass detection mechanisms."""
```

### **Integration Tests**
```python
def test_rate_limiting_endpoints():
    """Test rate limiting on actual endpoints."""
    
def test_bypass_detection_integration():
    """Test bypass detection in real scenarios."""
    
def test_redis_integration():
    """Test Redis-backed rate limiting."""
```

## 🚀 Best Practices

### **Rate Limiting Strategy**
- **Per-Endpoint Limits**: Different limits for different endpoints
- **User-Based Limits**: Per-user rate limiting for sensitive operations
- **IP-Based Limits**: IP-based limits for public endpoints
- **Burst Allowance**: Allow reasonable burst traffic

### **Bypass Prevention**
- **Multiple Detection Methods**: Combine multiple detection techniques
- **Machine Learning**: Use ML for pattern detection
- **Behavioral Analysis**: Analyze user behavior patterns
- **Real-time Response**: Immediate response to bypass attempts

### **Performance Optimization**
- **Caching**: Cache rate limit data for performance
- **Efficient Algorithms**: Choose appropriate algorithms for use cases
- **Distributed Limiting**: Use Redis for distributed rate limiting
- **Monitoring**: Monitor rate limiting performance

## 🔗 Related Documentation

- [Authentication System](../authentication/README.md) - User authentication flows
- [Authorization System](../authorization/README.md) - Access control and permissions
- [Token Management](../token-management/README.md) - JWT token security
- [Security Overview](../../security/overview.md) - Overall security architecture 