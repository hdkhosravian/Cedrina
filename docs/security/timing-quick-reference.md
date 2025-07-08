# Security Timing Quick Reference

## 🚀 Quick Setup (Copy & Paste)

```bash
# Add to your .env file
SECURITY_TIMING_SLOW_MIN=0.4      # Authentication failures: 400ms min
SECURITY_TIMING_SLOW_MAX=0.8      # Authentication failures: 800ms max
SECURITY_TIMING_MEDIUM_MIN=0.08   # Authorization errors: 80ms min
SECURITY_TIMING_MEDIUM_MAX=0.15   # Authorization errors: 150ms max
SECURITY_TIMING_FAST_MIN=0.02     # Validation errors: 20ms min
SECURITY_TIMING_FAST_MAX=0.05     # Validation errors: 50ms max
```

## ⚡ Quick Presets

### Powerful Servers (Default - Recommended)
```bash
SECURITY_TIMING_SLOW_MIN=0.4
SECURITY_TIMING_SLOW_MAX=0.8
```

### Extra Security (Slower)
```bash
SECURITY_TIMING_SLOW_MIN=0.5
SECURITY_TIMING_SLOW_MAX=1.0
```

### Less Powerful Servers (Faster)
```bash
SECURITY_TIMING_SLOW_MIN=0.2
SECURITY_TIMING_SLOW_MAX=0.4
```

### Development/Testing (Very Fast)
```bash
SECURITY_TIMING_SLOW_MIN=0.1
SECURITY_TIMING_SLOW_MAX=0.2
```

### Very Very Very Very Super Fast (Ultra Fast)
```bash
SECURITY_TIMING_SLOW_MIN=0.01
SECURITY_TIMING_SLOW_MAX=0.05
SECURITY_TIMING_MEDIUM_MIN=0.005
SECURITY_TIMING_MEDIUM_MAX=0.02
SECURITY_TIMING_FAST_MIN=0.001
SECURITY_TIMING_FAST_MAX=0.01
```

## 📊 What Each Pattern Does

| Pattern | Used For | Default Time | Security Level |
|---------|----------|--------------|----------------|
| **SLOW** | Authentication failures | 400-800ms | 🔴 High |
| **MEDIUM** | Authorization errors | 80-150ms | 🟡 Medium |
| **FAST** | Validation errors | 20-50ms | 🟢 Low |

## 🔧 All Settings

| Setting | Default | Range | Description |
|---------|---------|-------|-------------|
| `SECURITY_TIMING_SLOW_MIN` | 0.4s | 0.1-5.0s | Auth failures min time |
| `SECURITY_TIMING_SLOW_MAX` | 0.8s | 0.1-5.0s | Auth failures max time |
| `SECURITY_TIMING_MEDIUM_MIN` | 0.08s | 0.01-2.0s | Auth errors min time |
| `SECURITY_TIMING_MEDIUM_MAX` | 0.15s | 0.01-2.0s | Auth errors max time |
| `SECURITY_TIMING_FAST_MIN` | 0.02s | 0.01-1.0s | Validation min time |
| `SECURITY_TIMING_FAST_MAX` | 0.05s | 0.01-1.0s | Validation max time |

## 🧪 Quick Test

```bash
# Test authentication timing
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"wrong"}' \
  -w "Time: %{time_total}s\n"
```

**Expected:** ~400-800ms response time

## ❓ Common Issues

| Problem | Solution |
|---------|----------|
| Too slow | Reduce MAX values |
| Too fast | Increase MIN values |
| Inconsistent across servers | Set `SECURITY_SERVER_INSTANCE_ID` |
| Performance issues | Set `SECURITY_USE_ADVANCED_CRYPTO_OPERATIONS=false` |

## 📚 More Info

- **Full Guide:** `docs/security-timing-guide.md`
- **Configuration:** `docs/SECURITY_TIMING_CONFIG.md`
- **Example File:** `docs/timing-config-example.env`

---

**Remember:** Restart your application after changing timing settings! 