# Authorization System

Cedrina implements a comprehensive authorization system based on Role-Based Access Control (RBAC) and Attribute-Based Access Control (ABAC) using Casbin. This system provides granular permissions, dynamic policy management, and enterprise-grade security controls.

## 🏗️ Architecture Overview

### **Core Components**
- **Casbin Enforcer**: Central authorization engine with policy evaluation
- **Policy Service**: Domain service for policy management operations
- **Admin Endpoints**: REST API for dynamic policy management
- **Permission Dependencies**: FastAPI dependency injection for access control
- **ABAC Support**: Attribute-based policies with time, location, and department controls

### **Authorization Flow**
```
Request → Permission Check → Policy Evaluation → Access Decision
    ↓           ↓              ↓              ↓
FastAPI → Casbin Enforcer → Policy Rules → Allow/Deny
```

## 🔐 RBAC (Role-Based Access Control)

### **Core Concepts**
- **Subjects**: Users, roles, or groups that can perform actions
- **Objects**: Resources or endpoints that can be accessed
- **Actions**: Operations that can be performed (GET, POST, PUT, DELETE)
- **Policies**: Rules that define what subjects can do to objects

### **Policy Format**
```
subject, object, action
```

**Examples:**
```
admin, /api/v1/admin/users, GET
user, /api/v1/auth/profile, GET
admin, /api/v1/admin/policies, POST
```

## 🎯 ABAC (Attribute-Based Access Control)

### **Supported Attributes**
- **Department (sub_dept)**: User's department or organizational unit
- **Location (sub_loc)**: User's physical or logical location
- **Time of Day (time_of_day)**: Time-based access restrictions

### **Policy Format with Attributes**
```
subject, object, action, sub_dept, sub_loc, time_of_day
```

**Examples:**
```
user, /api/v1/reports, GET, engineering, us-west, 09:00-17:00
admin, /api/v1/admin/users, POST, hr, us-east, *
```

## 🛠️ Implementation Details

### **Policy Service**
```python
class PolicyService:
    """Domain service for policy management operations."""
    
    def add_policy(self, subject: str, object: str, action: str, 
                   performed_by: str, client_ip: str, user_agent: str,
                   attributes: Optional[Dict[str, str]] = None,
                   locale: str = "en") -> bool:
        """Add a new policy to the authorization system."""
        
    def remove_policy(self, subject: str, object: str, action: str,
                     performed_by: str, client_ip: str, user_agent: str,
                     locale: str = "en") -> bool:
        """Remove a policy from the authorization system."""
        
    def list_policies(self, performed_by: str, client_ip: str, 
                     user_agent: str, locale: str = "en") -> List[Dict[str, Any]]:
        """List all current policies."""
```

### **Permission Dependencies**
```python
def check_permission(object: str, action: str):
    """FastAPI dependency for permission checking."""
    
def get_current_admin_user():
    """Dependency for admin-only endpoints."""
```

## 📋 API Endpoints

### **Policy Management (Admin Only)**

#### **Add Policy**
```http
POST /api/v1/admin/policies/add
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "subject": "admin",
  "object": "/api/v1/admin/users",
  "action": "GET",
  "sub_dept": "engineering",
  "sub_loc": "us-west",
  "time_of_day": "09:00-17:00"
}
```

**Response:**
```json
{
  "message": "Policy added successfully",
  "subject": "admin",
  "object": "/api/v1/admin/users",
  "action": "GET",
  "attributes": {
    "sub_dept": "engineering",
    "sub_loc": "us-west",
    "time_of_day": "09:00-17:00"
  }
}
```

#### **Remove Policy**
```http
POST /api/v1/admin/policies/remove
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "subject": "user",
  "object": "/api/v1/reports",
  "action": "GET"
}
```

#### **List Policies**
```http
GET /api/v1/admin/policies
Authorization: Bearer <admin_token>
```

**Response:**
```json
{
  "policies": [
    {
      "subject": "admin",
      "object": "/api/v1/admin/users",
      "action": "GET",
      "attributes": {
        "sub_dept": "engineering"
      }
    }
  ],
  "count": 1
}
```

## 🔒 Security Features

### **Access Control**
- **Admin-Only Endpoints**: Policy management restricted to admin users
- **Rate Limiting**: 50/minute for policy operations, 100/minute for listing
- **Audit Logging**: All policy changes logged with user, IP, and timestamp
- **Input Validation**: Comprehensive validation of policy parameters

### **Policy Security**
- **Immutable Core**: Core system policies cannot be modified
- **Validation Rules**: Policy format and content validation
- **Conflict Resolution**: Duplicate policy handling
- **Rollback Support**: Policy removal for access revocation

### **ABAC Security**
- **Attribute Validation**: Time format, location codes, department validation
- **Dynamic Evaluation**: Real-time attribute checking
- **Context Awareness**: Request-time attribute evaluation
- **Fallback Handling**: Graceful degradation for missing attributes

## 🎨 Usage Examples

### **Basic RBAC Policy**
```python
# Allow admin users to access all admin endpoints
policy_service.add_policy("admin", "/api/v1/admin/*", "*")

# Allow regular users to access their own profile
policy_service.add_policy("user", "/api/v1/auth/profile", "GET")
```

### **ABAC Policy with Time Restrictions**
```python
# Allow engineering team to access reports during business hours
policy_service.add_policy(
    subject="user",
    object="/api/v1/reports",
    action="GET",
    attributes={
        "sub_dept": "engineering",
        "time_of_day": "09:00-17:00"
    }
)
```

### **Location-Based Access**
```python
# Allow US West users to access regional data
policy_service.add_policy(
    subject="user",
    object="/api/v1/regional-data",
    action="GET",
    attributes={
        "sub_loc": "us-west"
    }
)
```

## 🔧 Configuration

### **Casbin Configuration**
```python
# Policy file location
POLICY_FILE = "permissions/policy.csv"

# Model file location  
MODEL_FILE = "permissions/model.conf"

# Enable RBAC with domain support
ENABLE_RBAC = True

# Enable ABAC support
ENABLE_ABAC = True
```

### **Rate Limiting**
```python
# Policy management endpoints
POLICY_ADD_LIMIT = "50/minute"
POLICY_REMOVE_LIMIT = "50/minute"
POLICY_LIST_LIMIT = "100/minute"
```

## 🧪 Testing

### **Unit Tests**
```python
def test_add_policy_success():
    """Test successful policy addition."""
    
def test_remove_policy_success():
    """Test successful policy removal."""
    
def test_abac_policy_evaluation():
    """Test ABAC policy evaluation with attributes."""
```

### **Integration Tests**
```python
def test_admin_policy_management():
    """Test admin policy management endpoints."""
    
def test_permission_enforcement():
    """Test permission enforcement in protected endpoints."""
```

## 📊 Monitoring

### **Policy Metrics**
- **Policy Count**: Total number of active policies
- **Policy Changes**: Add/remove operations per time period
- **Access Decisions**: Allow/deny ratios by endpoint
- **Performance**: Policy evaluation response times

### **Security Monitoring**
- **Failed Access Attempts**: Unauthorized access attempts
- **Policy Violations**: Attempts to bypass policies
- **Admin Actions**: Policy management activities
- **Attribute Changes**: ABAC attribute modifications

## 🚀 Best Practices

### **Policy Design**
- **Principle of Least Privilege**: Grant minimum necessary permissions
- **Regular Review**: Periodic policy audit and cleanup
- **Documentation**: Clear policy documentation and purpose
- **Testing**: Comprehensive testing of policy combinations

### **Security Considerations**
- **Admin Access**: Restrict policy management to trusted administrators
- **Audit Trail**: Maintain complete audit logs of all changes
- **Validation**: Validate all policy inputs and attributes
- **Monitoring**: Monitor for unusual access patterns

### **Performance Optimization**
- **Caching**: Cache frequently accessed policies
- **Efficient Evaluation**: Optimize policy evaluation algorithms
- **Batch Operations**: Use batch operations for bulk policy changes
- **Indexing**: Index policies for fast lookup

## 🔗 Related Documentation

- [Authentication System](../authentication/README.md) - User authentication and session management
- [Token Management](../token-management/README.md) - JWT token security and management
- [Rate Limiting](../rate-limiting/README.md) - API rate limiting and abuse prevention
- [Security Overview](../../security/overview.md) - Overall security architecture and patterns 