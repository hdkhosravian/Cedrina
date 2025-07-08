# Security Timing Guide

## What is Security Timing?

Security timing prevents hackers from guessing passwords or finding valid usernames by making all similar operations take the same amount of time to respond.

**Example Problem:**
- Wrong password: 50ms response time
- User doesn't exist: 10ms response time
- **Hacker learns:** "User exists because response was slow!"

**Our Solution:**
- Wrong password: 400-800ms response time
- User doesn't exist: 400-800ms response time  
- **Hacker learns:** Nothing! Both responses take the same time.

## How It Works

### Timing Patterns

We use different timing patterns for different types of errors:

| Error Type | Timing Pattern | Response Time | Why? |
|------------|----------------|---------------|------|
| **Authentication failures** (wrong password, user not found) | SLOW | 400-800ms | Most sensitive - needs strongest protection |
| **Authorization errors** (insufficient permissions) | MEDIUM | 80-150ms | Medium sensitivity |
| **Validation errors** (bad input format) | FAST | 20-50ms | Least sensitive |

### What Gets Protected

✅ **All authentication failures return the same message:**
- Wrong password
- User doesn't exist  
- Account is locked
- Account is inactive
- Expired credentials

✅ **All responses take the same time:**
- Same timing pattern = same response time
- No information leaked about what actually failed

## Configuration Made Simple

### Quick Setup (Copy & Paste)

Add these to your `.env` file:

```bash
# Authentication failures - 400-800ms (recommended for powerful servers)
SECURITY_TIMING_SLOW_MIN=0.4
SECURITY_TIMING_SLOW_MAX=0.8

# Authorization errors - 80-150ms
SECURITY_TIMING_MEDIUM_MIN=0.08
SECURITY_TIMING_MEDIUM_MAX=0.15

# Validation errors - 20-50ms
SECURITY_TIMING_FAST_MIN=0.02
SECURITY_TIMING_FAST_MAX=0.05
```

### Ready-to-Use Examples

**For Powerful Servers (Default - Recommended):**
```bash
SECURITY_TIMING_SLOW_MIN=0.4
SECURITY_TIMING_SLOW_MAX=0.8
```

**For Extra Security (Slower responses):**
```bash
SECURITY_TIMING_SLOW_MIN=0.5
SECURITY_TIMING_SLOW_MAX=1.0
```

**For Less Powerful Servers (Faster responses):**
```bash
SECURITY_TIMING_SLOW_MIN=0.2
SECURITY_TIMING_SLOW_MAX=0.4
```

**For Development/Testing (Very fast):**
```bash
SECURITY_TIMING_SLOW_MIN=0.1
SECURITY_TIMING_SLOW_MAX=0.2
```

**For Very Very Very Very Super Fast (Ultra fast):**
```bash
SECURITY_TIMING_SLOW_MIN=0.01
SECURITY_TIMING_SLOW_MAX=0.05
SECURITY_TIMING_MEDIUM_MIN=0.005
SECURITY_TIMING_MEDIUM_MAX=0.02
SECURITY_TIMING_FAST_MIN=0.001
SECURITY_TIMING_FAST_MAX=0.01
```

## What Each Setting Does

### Basic Settings

| Setting | What It Controls | Default | Range |
|---------|------------------|---------|-------|
| `SECURITY_TIMING_SLOW_MIN` | Minimum time for authentication failures | 0.4s (400ms) | 0.1s - 5.0s |
| `SECURITY_TIMING_SLOW_MAX` | Maximum time for authentication failures | 0.8s (800ms) | 0.1s - 5.0s |
| `SECURITY_TIMING_MEDIUM_MIN` | Minimum time for authorization errors | 0.08s (80ms) | 0.01s - 2.0s |
| `SECURITY_TIMING_MEDIUM_MAX` | Maximum time for authorization errors | 0.15s (150ms) | 0.01s - 2.0s |
| `SECURITY_TIMING_FAST_MIN` | Minimum time for validation errors | 0.02s (20ms) | 0.01s - 1.0s |
| `SECURITY_TIMING_FAST_MAX` | Maximum time for validation errors | 0.05s (50ms) | 0.01s - 1.0s |

### Advanced Settings (Optional)

| Setting | What It Does | Default |
|---------|--------------|---------|
| `SECURITY_AUTO_DETECT_SERVER_PERFORMANCE` | Automatically adjust timing based on server power | `true` |
| `SECURITY_SERVER_PERFORMANCE_MULTIPLIER` | Manual performance adjustment (1.0 = normal) | `1.0` |
| `SECURITY_SERVER_INSTANCE_ID` | Unique ID for this server (for multi-server setups) | Auto-generated |
| `SECURITY_USE_ADVANCED_CRYPTO_OPERATIONS` | Use advanced security algorithms | `true` |

## Real-World Examples

### Scenario 1: User Login Attempt

**What happens when someone tries to log in:**

1. **User enters:** `username: john, password: wrong123`
2. **System checks:** User exists, password is wrong
3. **Response time:** 400-800ms (SLOW pattern)
4. **Response message:** "Invalid credentials" (generic message)
5. **Hacker learns:** Nothing useful!

### Scenario 2: Non-existent User

**What happens when someone tries a non-existent user:**

1. **User enters:** `username: nonexistent, password: anything`
2. **System checks:** User doesn't exist
3. **Response time:** 400-800ms (SLOW pattern) 
4. **Response message:** "Invalid credentials" (same generic message)
5. **Hacker learns:** Nothing useful!

### Scenario 3: Insufficient Permissions

**What happens when someone tries to access restricted resource:**

1. **User tries to access:** Admin panel
2. **System checks:** User lacks admin permissions
3. **Response time:** 80-150ms (MEDIUM pattern)
4. **Response message:** "Access denied" (generic message)
5. **Hacker learns:** Nothing useful!

## Common Questions

### Q: Why are the times so slow?
**A:** Slower responses make timing attacks much harder. 400-800ms is barely noticeable to users but makes attacks nearly impossible.

### Q: Can I make responses faster?
**A:** Yes! But faster responses are less secure. Use the "Less Powerful Servers", "Development", or "Very Very Very Very Super Fast" presets above.

### Q: What if my server is very powerful?
**A:** The system automatically detects server performance and adjusts timing. You can also use the "Extra Security" preset for even stronger protection.

### Q: Do I need to restart the application after changing settings?
**A:** Yes, restart the application for timing changes to take effect.

### Q: How do I know if it's working?
**A:** Check the logs for timing information, or use a tool like `curl` to measure response times for different error scenarios.

## Testing Your Configuration

### Quick Test with curl

```bash
# Test authentication failure timing
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"wrong"}' \
  -w "Response time: %{time_total}s\n"

# Test with non-existent user
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"nonexistent","password":"anything"}' \
  -w "Response time: %{time_total}s\n"
```

**Expected result:** Both requests should take similar time (400-800ms).

### Monitoring in Logs

Look for timing logs like:
```
{
  "event": "Standardized timing applied",
  "timing_pattern": "slow",
  "target_time": 0.6,
  "final_elapsed": 0.598
}
```

## Troubleshooting

### Problem: Responses are too slow
**Solution:** Reduce the MAX values:
```bash
SECURITY_TIMING_SLOW_MAX=0.6  # Instead of 0.8
```

### Problem: Responses are too fast
**Solution:** Increase the MIN values:
```bash
SECURITY_TIMING_SLOW_MIN=0.5  # Instead of 0.4
```

### Problem: Inconsistent timing across servers
**Solution:** Set unique server IDs:
```bash
SECURITY_SERVER_INSTANCE_ID=server-01
SECURITY_SERVER_INSTANCE_ID=server-02
```

### Problem: Performance issues
**Solution:** Disable advanced crypto operations:
```bash
SECURITY_USE_ADVANCED_CRYPTO_OPERATIONS=false
```

## Best Practices

### ✅ Do This
- Start with the default settings (they're optimized for powerful servers)
- Monitor response times to ensure they don't impact user experience
- Test timing consistency in staging before production
- Use correlation IDs for better debugging

### ❌ Don't Do This
- Don't set timing too fast (less than 200ms for authentication)
- Don't disable timing standardization
- Don't use different timing values across servers without testing
- Don't ignore timing logs in production

## Security Benefits

### What This Protects Against

1. **Password Guessing Attacks**
   - Can't tell if password is wrong or user doesn't exist
   - Can't determine which character is wrong

2. **User Enumeration**
   - Can't discover valid usernames
   - Can't build user lists for attacks

3. **Timing Attacks**
   - Can't measure response time differences
   - Can't extract sensitive information

4. **Brute Force Attacks**
   - Consistent timing makes attacks harder
   - No feedback about attack progress

### Compliance Benefits

- **OWASP Compliance:** Follows OWASP security guidelines
- **GDPR Compliance:** Prevents user enumeration (privacy protection)
- **SOC 2 Compliance:** Demonstrates security controls
- **PCI DSS Compliance:** Protects authentication systems

## Need Help?

- **Configuration Guide:** See `timing-config.md`
- **Example File:** Copy from `timing-config-example.env`
- **Code Documentation:** Check comments in `src/domain/security/error_standardization.py`

---

**Remember:** Security timing is invisible to legitimate users but makes attacks much harder. The default settings are optimized for powerful servers and provide excellent security. 