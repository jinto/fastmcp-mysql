# Security Guide for FastMCP MySQL Server

This guide provides detailed information about the security features and best practices for FastMCP MySQL Server.

## Overview

FastMCP MySQL Server includes enterprise-grade security features to protect your database from various threats:

- **SQL Injection Prevention**: Advanced pattern detection and parameter validation
- **Query Filtering**: Blacklist/whitelist modes to control allowed queries
- **Rate Limiting**: Prevent abuse with configurable rate limits
- **Security Logging**: Comprehensive audit trail for security events

## Security Features

### 1. SQL Injection Protection

The server uses multiple layers of protection against SQL injection:

#### Pattern Detection
- Classic injection patterns (e.g., `' OR '1'='1`)
- Union-based injection
- Blind injection (time-based and boolean-based)
- Encoded attacks (URL, Unicode, Hex encoding)
- Multi-statement attacks
- Comment-based injection

#### Example of Blocked Patterns
```sql
-- These queries will be blocked:
SELECT * FROM users WHERE id = '1' OR '1'='1'
SELECT * FROM users WHERE id = '1'; DROP TABLE users--'
SELECT * FROM users WHERE id = '1' UNION SELECT * FROM passwords
```

#### Safe Usage
Always use parameterized queries:
```python
# Safe
result = await mysql_query(
    "SELECT * FROM users WHERE id = %s",
    params=[user_id]
)

# Unsafe - will be blocked
result = await mysql_query(
    f"SELECT * FROM users WHERE id = '{user_id}'"
)
```

### 2. Query Filtering

Control which queries are allowed to execute:

#### Blacklist Mode (Default)
Blocks dangerous operations:
- DDL operations (CREATE, DROP, ALTER, TRUNCATE)
- System database access (information_schema, mysql, performance_schema)
- File operations (LOAD_FILE, INTO OUTFILE)
- User management (CREATE USER, GRANT, REVOKE)
- Dangerous functions (SLEEP, BENCHMARK, GET_LOCK)

#### Whitelist Mode
Only allows explicitly approved query patterns:
```bash
# Configure whitelist patterns (requires custom configuration)
MYSQL_FILTER_MODE=whitelist
MYSQL_WHITELIST_PATTERNS='["^SELECT .* FROM users WHERE id = %s$", "^INSERT INTO logs"]'
```

#### Combined Mode
Use both blacklist and whitelist for maximum control.

### 3. Rate Limiting

Protect against abuse with configurable rate limits:

#### Available Algorithms

1. **Token Bucket** (Default)
   - Allows burst traffic
   - Smooth rate limiting over time
   - Best for applications with occasional spikes

2. **Sliding Window**
   - Strict rate enforcement
   - No burst allowance
   - Best for consistent rate limiting

3. **Fixed Window**
   - Simple time-based windows
   - Resets at fixed intervals
   - Most performant option

#### Configuration Examples

```bash
# Basic rate limiting (60 requests per minute)
MYSQL_RATE_LIMIT_RPM=60
MYSQL_RATE_LIMIT_BURST=10

# Strict rate limiting with sliding window
MYSQL_RATE_LIMIT_ALGORITHM=sliding_window
MYSQL_RATE_LIMIT_RPM=60

# High-traffic application
MYSQL_RATE_LIMIT_RPM=600
MYSQL_RATE_LIMIT_BURST=50
MYSQL_RATE_LIMIT_ALGORITHM=token_bucket
```

#### Per-User Rate Limits
Configure different limits for different users (requires custom implementation):
```python
# In your application code
rate_limits = {
    "premium_user": 120,  # 120 requests per minute
    "basic_user": 30,     # 30 requests per minute
}
```

### 4. Security Logging

Monitor security events with comprehensive logging:

```bash
# Enable all security logging
MYSQL_LOG_SECURITY_EVENTS=true
MYSQL_LOG_REJECTED_QUERIES=true
MYSQL_AUDIT_ALL_QUERIES=false  # Enable only for debugging

# Log format (JSON)
{
  "timestamp": "2024-01-15T10:30:45Z",
  "level": "WARNING",
  "message": "Security event: injection_detected",
  "event_type": "injection_detected",
  "details": {
    "query": "SELECT * FROM users WHERE...",
    "threats": ["SQL injection detected"],
    "user": "user_123"
  }
}
```

## Security Configurations

### Development Environment
Balanced security with debugging capabilities:
```bash
MYSQL_ENABLE_SECURITY=true
MYSQL_ENABLE_INJECTION_DETECTION=true
MYSQL_ENABLE_RATE_LIMITING=true
MYSQL_FILTER_MODE=blacklist
MYSQL_RATE_LIMIT_RPM=120
MYSQL_RATE_LIMIT_BURST=20
MYSQL_LOG_SECURITY_EVENTS=true
MYSQL_LOG_REJECTED_QUERIES=true
```

### Production Environment
Maximum security with performance optimization:
```bash
MYSQL_ENABLE_SECURITY=true
MYSQL_ENABLE_INJECTION_DETECTION=true
MYSQL_ENABLE_RATE_LIMITING=true
MYSQL_FILTER_MODE=combined
MYSQL_RATE_LIMIT_RPM=60
MYSQL_RATE_LIMIT_BURST=10
MYSQL_RATE_LIMIT_ALGORITHM=token_bucket
MYSQL_MAX_QUERY_LENGTH=5000
MYSQL_LOG_SECURITY_EVENTS=true
MYSQL_LOG_REJECTED_QUERIES=false  # Reduce log volume
MYSQL_AUDIT_ALL_QUERIES=false
```

### High-Security Environment
For sensitive data:
```bash
MYSQL_ENABLE_SECURITY=true
MYSQL_ENABLE_INJECTION_DETECTION=true
MYSQL_ENABLE_RATE_LIMITING=true
MYSQL_FILTER_MODE=whitelist  # Only allow specific queries
MYSQL_RATE_LIMIT_RPM=30
MYSQL_RATE_LIMIT_BURST=5
MYSQL_RATE_LIMIT_ALGORITHM=sliding_window
MYSQL_MAX_QUERY_LENGTH=2000
MYSQL_MAX_PARAMETER_LENGTH=500
MYSQL_LOG_SECURITY_EVENTS=true
MYSQL_LOG_REJECTED_QUERIES=true
MYSQL_AUDIT_ALL_QUERIES=true  # Full audit trail
```

## Best Practices

### 1. Use Parameterized Queries
Always use parameters instead of string concatenation:
```python
# Good
await mysql_query("SELECT * FROM users WHERE age > %s", params=[18])

# Bad
await mysql_query(f"SELECT * FROM users WHERE age > {user_age}")
```

### 2. Principle of Least Privilege
- Only enable write operations when necessary
- Use read-only connections for reporting
- Limit database user permissions

### 3. Regular Security Audits
- Review security logs regularly
- Monitor for unusual patterns
- Update security rules based on threats

### 4. Defense in Depth
- Use multiple security layers
- Don't rely on a single security feature
- Combine with network security measures

### 5. Keep Updated
- Regularly update FastMCP MySQL Server
- Monitor security advisories
- Apply patches promptly

## Troubleshooting

### Query Rejected by Security
1. Check security logs for details
2. Verify query doesn't match blocked patterns
3. Consider adding to whitelist if legitimate

### Rate Limit Exceeded
1. Check current rate limit settings
2. Consider increasing limits for legitimate use
3. Implement client-side rate limiting

### False Positives
1. Review injection detection patterns
2. Use parameterized queries
3. Consider custom filtering rules

## Security Reporting

If you discover a security vulnerability, please report it to:
- Email: security@example.com (update with your email)
- Do not disclose publicly until fixed

## Compliance

FastMCP MySQL Server's security features help with:
- OWASP Top 10 compliance (SQL Injection)
- PCI DSS requirements (logging, access control)
- GDPR (audit trails, access control)
- SOC 2 (security monitoring)