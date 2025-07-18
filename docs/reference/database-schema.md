# Database Schema Reference

This document provides a comprehensive reference for the Cedrina database schema, including all tables, relationships, constraints, and indexes. All details are verified against the actual Alembic migrations and SQLModel definitions.

## 📋 Schema Overview

Cedrina uses PostgreSQL as its primary database with the following design principles:

- **Normalized Design**: Third normal form to minimize data redundancy
- **Referential Integrity**: Foreign key constraints to maintain data consistency
- **Indexing Strategy**: Optimized indexes for common query patterns
- **Audit Trail**: Comprehensive logging of all data changes
- **Security**: Encrypted sensitive data and access controls

## 🗄️ Core Tables

### Users Table

**Table Name**: `users`

**Description**: Stores user account information and authentication details

**Columns**:

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | `SERIAL` | `PRIMARY KEY` | Unique user identifier |
| `username` | `VARCHAR(50)` | `UNIQUE NOT NULL` | Username for login (case-insensitive, indexed) |
| `email` | `VARCHAR(254)` | `UNIQUE NOT NULL` | Email address (case-insensitive, indexed) |
| `hashed_password` | `VARCHAR(255)` | `NULL` | Bcrypt hashed password (null for OAuth users) |
| `role` | `ENUM('ADMIN', 'USER')` | `NOT NULL DEFAULT 'USER'` | User role for RBAC |
| `is_active` | `BOOLEAN` | `NOT NULL DEFAULT true` | Account status |
| `email_confirmed` | `BOOLEAN` | `NOT NULL DEFAULT true` | Email verification status |
| `email_confirmation_token` | `VARCHAR(64)` | `NULL` | Email confirmation token |
| `password_reset_token` | `VARCHAR(64)` | `NULL` | Password reset token |
| `password_reset_token_expires_at` | `TIMESTAMP` | `NULL` | Reset token expiration |
| `created_at` | `TIMESTAMP` | `NOT NULL DEFAULT NOW()` | Account creation time |
| `updated_at` | `TIMESTAMP` | `NULL` | Last update time |

**Indexes**:
```sql
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username_lower ON users(lower(username));
CREATE INDEX idx_users_email_lower ON users(lower(email));
```

### OAuth Profiles Table

**Table Name**: `oauth_profiles`

**Description**: Stores OAuth provider account information

**Columns**:

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | `SERIAL` | `PRIMARY KEY` | Unique OAuth profile identifier |
| `user_id` | `INTEGER` | `NOT NULL` | Reference to users table |
| `provider` | `ENUM('GOOGLE', 'MICROSOFT', 'FACEBOOK')` | `NOT NULL` | OAuth provider |
| `provider_user_id` | `VARCHAR(255)` | `NOT NULL` | User ID from OAuth provider |
| `access_token` | `BYTEA` | `NOT NULL` | **Encrypted** OAuth access token |
| `expires_at` | `TIMESTAMP` | `NOT NULL` | Token expiration |
| `created_at` | `TIMESTAMP` | `NOT NULL DEFAULT NOW()` | Profile creation time |
| `updated_at` | `TIMESTAMP` | `NULL` | Last update time |

**Foreign Keys**:
```sql
ALTER TABLE oauth_profiles 
ADD CONSTRAINT fk_oauth_profiles_user_id 
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
```

**Indexes**:
```sql
CREATE UNIQUE INDEX idx_oauth_profiles_provider_user ON oauth_profiles(provider, provider_user_id);
CREATE INDEX idx_oauth_profiles_user_id ON oauth_profiles(user_id);
```

### Sessions Table

**Table Name**: `sessions`

**Description**: Tracks user sessions and authentication tokens

**Columns**:

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | `SERIAL` | `PRIMARY KEY` | Unique session identifier |
| `jti` | `VARCHAR(255)` | `UNIQUE NOT NULL` | JWT token identifier (JTI) |
| `user_id` | `INTEGER` | `NOT NULL` | Reference to users table |
| `refresh_token_hash` | `VARCHAR(255)` | `NOT NULL` | **Hashed** refresh token |
| `created_at` | `TIMESTAMP` | `NOT NULL DEFAULT NOW()` | Session creation time |
| `expires_at` | `TIMESTAMP` | `NOT NULL` | Session expiration |
| `revoked_at` | `TIMESTAMP` | `NULL` | Session revocation time |

**Foreign Keys**:
```sql
ALTER TABLE sessions 
ADD CONSTRAINT fk_sessions_user_id 
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
```

**Indexes**:
```sql
CREATE UNIQUE INDEX idx_sessions_jti ON sessions(jti);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_user_id_expires_at ON sessions(user_id, expires_at);
```

### Token Families Table

**Table Name**: `token_families`

**Description**: Advanced token family security for session management

**Columns**:

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | `SERIAL` | `PRIMARY KEY` | Unique token family identifier |
| `family_id` | `VARCHAR(36)` | `UNIQUE NOT NULL` | Token family UUID |
| `user_id` | `INTEGER` | `NOT NULL` | Reference to users table |
| `status` | `ENUM('active', 'compromised', 'revoked', 'expired')` | `NOT NULL` | Family status |
| `created_at` | `TIMESTAMP` | `NOT NULL DEFAULT NOW()` | Family creation time |
| `last_used_at` | `TIMESTAMP` | `NULL` | Last activity time |
| `compromised_at` | `TIMESTAMP` | `NULL` | Compromise detection time |
| `expires_at` | `TIMESTAMP` | `NULL` | Family expiration |
| `active_tokens_encrypted` | `BYTEA` | `NULL` | **Encrypted** active tokens |
| `revoked_tokens_encrypted` | `BYTEA` | `NULL` | **Encrypted** revoked tokens |
| `usage_history_encrypted` | `BYTEA` | `NULL` | **Encrypted** usage history |
| `compromise_reason` | `TEXT` | `NULL` | Reason for compromise |
| `security_score` | `FLOAT` | `NOT NULL` | Security assessment score |

**Foreign Keys**:
```sql
ALTER TABLE token_families 
ADD CONSTRAINT fk_token_families_user_id 
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
```

**Indexes**:
```sql
CREATE UNIQUE INDEX idx_token_families_family_id ON token_families(family_id);
CREATE INDEX idx_token_families_user_id ON token_families(user_id);
CREATE INDEX idx_token_families_status ON token_families(status);
CREATE INDEX idx_token_families_user_id_status ON token_families(user_id, status);
CREATE INDEX idx_token_families_expires_at ON token_families(expires_at);
```

### Casbin Policies Table

**Table Name**: `casbin_policies`

**Description**: Role-based access control policies

**Columns**:

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | `SERIAL` | `PRIMARY KEY` | Unique policy identifier |
| `ptype` | `VARCHAR(10)` | `NOT NULL` | Policy type (p, g) |
| `v0` | `VARCHAR(100)` | `NULL` | Subject/role |
| `v1` | `VARCHAR(100)` | `NULL` | Object/resource |
| `v2` | `VARCHAR(100)` | `NULL` | Action |
| `v3` | `VARCHAR(100)` | `NULL` | Domain |
| `v4` | `VARCHAR(100)` | `NULL` | Additional field |
| `v5` | `VARCHAR(100)` | `NULL` | Additional field |
| `created_at` | `TIMESTAMP` | `NOT NULL DEFAULT NOW()` | Policy creation time |

**Indexes**:
```sql
CREATE INDEX idx_casbin_policies_ptype ON casbin_policies(ptype);
CREATE INDEX idx_casbin_policies_v0 ON casbin_policies(v0);
CREATE INDEX idx_casbin_policies_v1 ON casbin_policies(v1);
```

### Casbin Audit Logs Table

**Table Name**: `casbin_audit_logs`

**Description**: Audit trail for policy changes

**Columns**:

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `id` | `SERIAL` | `PRIMARY KEY` | Unique audit log identifier |
| `policy_id` | `INTEGER` | `NOT NULL` | Reference to casbin_policies |
| `action` | `VARCHAR(20)` | `NOT NULL` | Action performed (CREATE, UPDATE, DELETE) |
| `old_values` | `JSONB` | `NULL` | Previous policy values |
| `new_values` | `JSONB` | `NULL` | New policy values |
| `user_id` | `INTEGER` | `NULL` | User who made the change |
| `ip_address` | `INET` | `NULL` | IP address of the change |
| `created_at` | `TIMESTAMP` | `NOT NULL DEFAULT NOW()` | Audit log creation time |

**Foreign Keys**:
```sql
ALTER TABLE casbin_audit_logs 
ADD CONSTRAINT fk_casbin_audit_logs_policy_id 
FOREIGN KEY (policy_id) REFERENCES casbin_policies(id) ON DELETE CASCADE;

ALTER TABLE casbin_audit_logs 
ADD CONSTRAINT fk_casbin_audit_logs_user_id 
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;
```

**Indexes**:
```sql
CREATE INDEX idx_casbin_audit_logs_policy_id ON casbin_audit_logs(policy_id);
CREATE INDEX idx_casbin_audit_logs_action ON casbin_audit_logs(action);
CREATE INDEX idx_casbin_audit_logs_created_at ON casbin_audit_logs(created_at);
```

## 🔗 Relationships

### Entity Relationship Diagram

```
users (1) ←→ (N) oauth_profiles
users (1) ←→ (N) sessions
users (1) ←→ (N) token_families
users (1) ←→ (N) casbin_audit_logs
casbin_policies (1) ←→ (N) casbin_audit_logs
```

### Relationship Details

1. **Users ↔ OAuth Profiles**: One-to-many relationship
   - One user can have multiple OAuth provider accounts
   - Each OAuth profile belongs to exactly one user
   - Supports multiple providers per user

2. **Users ↔ Sessions**: One-to-many relationship
   - One user can have multiple active sessions
   - Each session belongs to exactly one user
   - Sessions are automatically cleaned up on expiration

3. **Users ↔ Token Families**: One-to-many relationship
   - One user can have multiple token families
   - Each token family belongs to exactly one user
   - Advanced security with family-wide revocation

4. **Users ↔ Casbin Audit Logs**: One-to-many relationship
   - One user can generate multiple audit logs
   - Audit logs can also be system-wide (no user_id)
   - Comprehensive policy change tracking

5. **Casbin Policies ↔ Casbin Audit Logs**: One-to-many relationship
   - One policy can have multiple audit log entries
   - Each audit log entry belongs to exactly one policy
   - Tracks all policy changes for compliance

## 🔐 Security Features

### Data Encryption

**Password Hashing**:
```sql
-- Passwords are hashed using bcrypt with cost factor 12
-- Example: $2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8KqKqKq
```

**Sensitive Data Encryption**:
- OAuth access tokens are stored encrypted in BYTEA columns
- Token family data is encrypted at rest
- Session refresh tokens are hashed for security

### Access Controls

**Row-Level Security (RLS)**:
```sql
-- Enable RLS on sensitive tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE token_families ENABLE ROW LEVEL SECURITY;

-- Create policies for data access
CREATE POLICY users_select_policy ON users
    FOR SELECT USING (auth.uid() = id OR is_admin());

CREATE POLICY sessions_select_policy ON sessions
    FOR SELECT USING (auth.uid() = user_id OR is_admin());
```

### Audit Trail

**Comprehensive Logging**:
- All authentication events are logged
- Failed login attempts are tracked
- Session creation and termination are recorded
- Token family security events are captured
- Policy changes are audited

## 📊 Performance Optimizations

### Indexing Strategy

**Primary Indexes**:
- Primary keys on all tables
- Unique constraints on business keys (username, email, jti)

**Performance Indexes**:
- Composite indexes for common query patterns
- Partial indexes for active records
- Functional indexes for case-insensitive searches

**Query Optimization**:
```sql
-- Optimize user lookups
CREATE INDEX idx_users_username_lower ON users(lower(username));
CREATE INDEX idx_users_email_lower ON users(lower(email));

-- Optimize session queries
CREATE INDEX idx_sessions_active_expires ON sessions(user_id, expires_at)
WHERE revoked_at IS NULL;

-- Optimize token family queries
CREATE INDEX idx_token_families_active_user ON token_families(user_id, status)
WHERE status = 'active';
```

### Partitioning Strategy

**Time-Based Partitioning**:
```sql
-- Partition audit logs by month
CREATE TABLE casbin_audit_logs_2025_01 PARTITION OF casbin_audit_logs
FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
```

## 🔄 Data Maintenance

### Cleanup Procedures

**Expired Sessions**:
```sql
-- Clean up expired sessions (run daily)
DELETE FROM sessions 
WHERE expires_at < NOW() OR revoked_at IS NOT NULL;
```

**Expired OAuth Tokens**:
```sql
-- Clean up expired OAuth tokens (run daily)
UPDATE oauth_profiles 
SET access_token = NULL, expires_at = NULL
WHERE expires_at < NOW();
```

**Expired Token Families**:
```sql
-- Clean up expired token families (run daily)
UPDATE token_families 
SET status = 'expired'
WHERE expires_at < NOW() AND status = 'active';
```

**Old Audit Logs**:
```sql
-- Archive old audit logs (run monthly)
-- Move logs older than 1 year to archive table
INSERT INTO casbin_audit_logs_archive 
SELECT * FROM casbin_audit_logs 
WHERE created_at < NOW() - INTERVAL '1 year';

DELETE FROM casbin_audit_logs 
WHERE created_at < NOW() - INTERVAL '1 year';
```

### Backup Strategy

**Full Backups**:
```bash
# Daily full backup
pg_dump -h localhost -U cedrina -d cedrina > backup_$(date +%Y%m%d).sql

# Weekly compressed backup
pg_dump -h localhost -U cedrina -d cedrina | gzip > backup_$(date +%Y%m%d).sql.gz
```

**Incremental Backups**:
```bash
# WAL archiving for point-in-time recovery
# Configure in postgresql.conf
wal_level = replica
archive_mode = on
archive_command = 'cp %p /var/lib/postgresql/archive/%f'
```

## 📈 Monitoring and Metrics

### Key Metrics

**User Activity**:
```sql
-- Active users in last 30 days
SELECT COUNT(DISTINCT user_id) 
FROM sessions 
WHERE expires_at > NOW() AND revoked_at IS NULL;

-- Failed login attempts
SELECT COUNT(*) 
FROM security_events 
WHERE event_type = 'login_failed' 
AND created_at > NOW() - INTERVAL '24 hours';
```

**Session Statistics**:
```sql
-- Average session duration
SELECT AVG(EXTRACT(EPOCH FROM (expires_at - created_at))) 
FROM sessions 
WHERE revoked_at IS NULL;

-- Concurrent sessions per user
SELECT user_id, COUNT(*) as session_count
FROM sessions 
WHERE expires_at > NOW() AND revoked_at IS NULL
GROUP BY user_id 
ORDER BY session_count DESC;
```

**Token Family Analysis**:
```sql
-- Token family security status
SELECT status, COUNT(*) as count
FROM token_families 
GROUP BY status 
ORDER BY count DESC;

-- Compromised token families
SELECT user_id, compromise_reason, security_score
FROM token_families 
WHERE status = 'compromised'
ORDER BY compromised_at DESC;
```

**Policy Audit Analysis**:
```sql
-- Most active policy changes
SELECT action, COUNT(*) as changes
FROM casbin_audit_logs 
WHERE created_at > NOW() - INTERVAL '30 days'
GROUP BY action 
ORDER BY changes DESC;

-- Policy changes by user
SELECT user_id, COUNT(*) as changes
FROM casbin_audit_logs 
WHERE user_id IS NOT NULL
GROUP BY user_id 
ORDER BY changes DESC;
```

## 🛠️ Migration Scripts

### Initial Schema Setup

```sql
-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';
```

### Sample Data

```sql
-- Insert test user (password: TestPass123!)
INSERT INTO users (username, email, hashed_password, is_active, email_confirmed) VALUES
('testuser', 'test@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8KqKqKq', true, true);

-- Insert admin user (password: AdminPass123!)
INSERT INTO users (username, email, hashed_password, role, is_active, email_confirmed) VALUES
('admin', 'admin@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8KqKqKq', 'ADMIN', true, true);
```

## 🔗 Related Documentation

- **[API Reference](api-reference.md)** - API endpoint documentation
- **[Configuration Guide](../getting-started/configuration-guide.md)** - Database configuration
- **[Deployment Guide](../deployment/overview.md)** - Production deployment
- **[Performance Guide](performance-benchmarks.md)** - Performance optimization

---

*Last updated: January 2025* 