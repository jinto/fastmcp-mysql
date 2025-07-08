# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with FastMCP MySQL Server.

## Table of Contents

1. [Connection Issues](#connection-issues)
2. [Query Execution Problems](#query-execution-problems)
3. [Security & Permission Issues](#security--permission-issues)
4. [Performance Problems](#performance-problems)
5. [Configuration Issues](#configuration-issues)
6. [Installation Problems](#installation-problems)
7. [Diagnostic Tools](#diagnostic-tools)
8. [Getting Help](#getting-help)

## Connection Issues

### Error: "Connection refused" or "Can't connect to MySQL server"

**Symptoms:**
```
Error: Can't connect to MySQL server on 'localhost' (111)
```

**Solutions:**

1. **Verify MySQL is running:**
   ```bash
   # Linux/macOS
   sudo systemctl status mysql
   # or
   sudo service mysql status
   
   # Check if MySQL is listening
   netstat -an | grep 3306
   ```

2. **Check connection parameters:**
   ```bash
   # Test connection manually
   mysql -h localhost -u your_user -p your_database
   ```

3. **Verify environment variables:**
   ```bash
   echo $MYSQL_HOST
   echo $MYSQL_PORT
   echo $MYSQL_USER
   ```

4. **Check firewall settings:**
   ```bash
   # Ubuntu/Debian
   sudo ufw status
   
   # CentOS/RHEL
   sudo firewall-cmd --list-all
   ```

### Error: "Access denied for user"

**Symptoms:**
```
Error: Access denied for user 'user'@'host' (using password: YES)
```

**Solutions:**

1. **Verify credentials:**
   ```sql
   -- Connect as root and check user
   SELECT user, host FROM mysql.user WHERE user = 'your_user';
   ```

2. **Grant proper permissions:**
   ```sql
   GRANT SELECT ON database_name.* TO 'user'@'host';
   FLUSH PRIVILEGES;
   ```

3. **Check password:**
   - Ensure no special characters need escaping
   - Try setting password in MySQL directly

### Error: "Too many connections"

**Symptoms:**
```
Error: Too many connections
```

**Solutions:**

1. **Increase MySQL connection limit:**
   ```sql
   SHOW VARIABLES LIKE 'max_connections';
   SET GLOBAL max_connections = 200;
   ```

2. **Reduce pool size:**
   ```bash
   MYSQL_POOL_SIZE=5  # Lower than MySQL max_connections
   ```

3. **Check for connection leaks:**
   ```python
   metrics = await mysql_metrics()
   print(metrics['connection_pool'])
   ```

## Query Execution Problems

### Error: "Query execution timeout"

**Symptoms:**
```
Error: Query execution timeout after 30000ms
```

**Solutions:**

1. **Increase timeout:**
   ```bash
   MYSQL_QUERY_TIMEOUT=60000  # 60 seconds
   ```

2. **Optimize query:**
   - Add appropriate indexes
   - Use EXPLAIN to analyze query
   - Limit result set size

3. **Check slow query log:**
   ```sql
   SHOW VARIABLES LIKE 'slow_query_log%';
   ```

### Error: "Syntax error in SQL query"

**Symptoms:**
```
Error: You have an error in your SQL syntax
```

**Solutions:**

1. **Validate SQL syntax:**
   ```python
   # Test query directly in MySQL client
   mysql> SELECT * FROM users WHERE id = 1;
   ```

2. **Check for typos:**
   - Table names
   - Column names
   - SQL keywords

3. **Verify parameter placeholders:**
   ```python
   # Correct
   await mysql_query("SELECT * FROM users WHERE id = %s", params=[1])
   
   # Incorrect
   await mysql_query("SELECT * FROM users WHERE id = ?", params=[1])
   ```

### Error: "Table doesn't exist"

**Symptoms:**
```
Error: Table 'database.table_name' doesn't exist
```

**Solutions:**

1. **Check table exists:**
   ```sql
   SHOW TABLES;
   -- or
   SELECT * FROM information_schema.tables 
   WHERE table_schema = 'your_database';
   ```

2. **Verify database selection:**
   ```bash
   echo $MYSQL_DB  # Check correct database
   ```

3. **Check case sensitivity:**
   - Linux: Table names are case-sensitive
   - Windows/macOS: Usually case-insensitive

## Security & Permission Issues

### Error: "SQL injection detected"

**Symptoms:**
```
Error: SQL injection attempt detected
```

**Solutions:**

1. **Use parameterized queries:**
   ```python
   # Wrong
   query = f"SELECT * FROM users WHERE name = '{user_input}'"
   
   # Correct
   await mysql_query(
       "SELECT * FROM users WHERE name = %s",
       params=[user_input]
   )
   ```

2. **Check for special characters:**
   - Single quotes
   - Semicolons
   - SQL keywords in strings

3. **Review security logs:**
   ```bash
   # Check what triggered the detection
   tail -f /var/log/fastmcp-mysql/security.log
   ```

### Error: "Operation not permitted"

**Symptoms:**
```
Error: INSERT operations are not allowed
```

**Solutions:**

1. **Enable write operations:**
   ```bash
   MYSQL_ALLOW_INSERT=true
   MYSQL_ALLOW_UPDATE=true
   MYSQL_ALLOW_DELETE=true
   ```

2. **Check filter mode:**
   ```bash
   # For whitelist mode, ensure query is allowed
   MYSQL_FILTER_MODE=blacklist  # More permissive
   ```

### Error: "Rate limit exceeded"

**Symptoms:**
```
Error: Rate limit exceeded. Try again later.
```

**Solutions:**

1. **Increase rate limits:**
   ```bash
   MYSQL_RATE_LIMIT_RPM=120  # 120 requests per minute
   MYSQL_RATE_LIMIT_BURST=20
   ```

2. **Implement backoff:**
   ```python
   import asyncio
   
   for attempt in range(3):
       result = await mysql_query(query)
       if result['success']:
           break
       if "rate limit" in result.get('error', ''):
           await asyncio.sleep(2 ** attempt)  # Exponential backoff
   ```

3. **Use different rate limit algorithm:**
   ```bash
   MYSQL_RATE_LIMIT_ALGORITHM=token_bucket  # Allows bursts
   ```

## Performance Problems

### Slow Query Performance

**Symptoms:**
- Queries taking longer than expected
- High p95/p99 latencies

**Solutions:**

1. **Enable query caching:**
   ```bash
   MYSQL_CACHE_ENABLED=true
   MYSQL_CACHE_MAX_SIZE=2000
   MYSQL_CACHE_TTL=300000  # 5 minutes
   ```

2. **Analyze query performance:**
   ```python
   # Check metrics
   metrics = await mysql_metrics()
   print(metrics['query']['duration_percentiles_ms'])
   
   # Find slow queries
   print(metrics['query']['slow_queries'])
   ```

3. **Optimize database:**
   ```sql
   -- Add indexes
   CREATE INDEX idx_user_email ON users(email);
   
   -- Analyze tables
   ANALYZE TABLE users;
   
   -- Check query plan
   EXPLAIN SELECT * FROM users WHERE email = 'test@example.com';
   ```

### High Memory Usage

**Symptoms:**
- Server consuming excessive memory
- Out of memory errors

**Solutions:**

1. **Reduce pool and cache size:**
   ```bash
   MYSQL_POOL_SIZE=5
   MYSQL_CACHE_MAX_SIZE=500
   ```

2. **Enable streaming for large results:**
   ```bash
   MYSQL_STREAMING_CHUNK_SIZE=100
   ```

3. **Use pagination:**
   ```python
   # Instead of
   await mysql_query("SELECT * FROM large_table")
   
   # Use
   await mysql_query("SELECT * FROM large_table LIMIT 100 OFFSET 0")
   ```

## Configuration Issues

### Environment Variables Not Loading

**Symptoms:**
- Settings not taking effect
- Using default values unexpectedly

**Solutions:**

1. **Check variable names:**
   ```bash
   # All MySQL variables must start with MYSQL_
   MYSQL_HOST=localhost  # Correct
   HOST=localhost        # Wrong
   ```

2. **Verify in Claude Desktop config:**
   ```json
   {
     "mcpServers": {
       "mysql": {
         "env": {
           "MYSQL_HOST": "localhost"  // Check spelling
         }
       }
     }
   }
   ```

3. **Debug environment:**
   ```python
   import os
   print(os.environ.get('MYSQL_HOST'))
   ```

### Invalid Configuration Values

**Symptoms:**
```
Error: Invalid value for MYSQL_POOL_SIZE
```

**Solutions:**

1. **Check value types:**
   ```bash
   MYSQL_POOL_SIZE=10        # Correct (integer)
   MYSQL_POOL_SIZE="ten"     # Wrong (string)
   
   MYSQL_ALLOW_INSERT=true   # Correct (boolean)
   MYSQL_ALLOW_INSERT=1      # Wrong (use true/false)
   ```

2. **Verify ranges:**
   - Pool size: 1-100
   - Rate limit: 1-10000 RPM
   - Cache size: 1-10000

## Installation Problems

### Module Not Found

**Symptoms:**
```
ModuleNotFoundError: No module named 'fastmcp_mysql'
```

**Solutions:**

1. **Ensure proper installation:**
   ```bash
   # Using uvx (recommended)
   uvx fastmcp-mysql
   
   # Or pip
   pip install fastmcp-mysql
   
   # Or from source
   uv sync --all-extras
   ```

2. **Check Python version:**
   ```bash
   python --version  # Must be 3.10+
   ```

3. **Verify virtual environment:**
   ```bash
   which python  # Should point to venv
   ```

### Dependency Conflicts

**Symptoms:**
```
ERROR: pip's dependency resolver does not currently take into account all the packages that are installed
```

**Solutions:**

1. **Use uv for dependency management:**
   ```bash
   # Install uv
   pip install uv
   
   # Sync dependencies
   uv sync
   ```

2. **Create clean environment:**
   ```bash
   python -m venv fresh_env
   source fresh_env/bin/activate
   pip install fastmcp-mysql
   ```

## Diagnostic Tools

### Built-in Health Check

```python
# Check system health
health = await mysql_health()
print(json.dumps(health, indent=2))

# Interpret results
for component in health['components']:
    if component['status'] != 'healthy':
        print(f"Issue with {component['name']}: {component['message']}")
```

### Debug Mode

```bash
# Enable debug logging
export MYSQL_LOG_LEVEL=DEBUG

# Enable all security logging
export MYSQL_LOG_SECURITY_EVENTS=true
export MYSQL_LOG_REJECTED_QUERIES=true
export MYSQL_AUDIT_ALL_QUERIES=true
```

### Performance Profiling

```python
# Get detailed metrics
metrics = await mysql_metrics()

# Check specific areas
print("Query performance:", metrics['query']['duration_percentiles_ms'])
print("Cache efficiency:", metrics['cache']['hit_rate_percent'])
print("Pool usage:", metrics['connection_pool']['utilization_percent'])
print("Error rate:", metrics['query']['error_rate'])
```

### Connection Test Script

```python
# test_connection.py
import asyncio
import os

async def test_connection():
    from fastmcp_mysql.server import create_server
    
    try:
        server = await create_server()
        result = await server.mysql_query("SELECT 1 as test")
        print("Connection successful:", result)
    except Exception as e:
        print("Connection failed:", e)
        
asyncio.run(test_connection())
```

## Getting Help

### Before Asking for Help

1. **Check this guide thoroughly**
2. **Review the FAQ**
3. **Search existing issues**
4. **Try debug mode**
5. **Collect relevant information:**
   - Error messages
   - Configuration
   - MySQL version
   - Python version
   - Operating system

### Where to Get Help

1. **GitHub Issues**: For bugs and feature requests
   - Include minimal reproduction steps
   - Provide full error messages
   - List your configuration (hide passwords)

2. **GitHub Discussions**: For questions and help
   - Search before posting
   - Provide context
   - Share what you've tried

3. **Security Issues**: Email security@example.com
   - Don't post security issues publicly
   - Include details privately

### Information to Provide

When seeking help, include:

```markdown
**Environment:**
- OS: [e.g., Ubuntu 22.04]
- Python: [e.g., 3.11.0]
- MySQL: [e.g., 8.0.35]
- FastMCP MySQL: [e.g., 1.0.0]

**Configuration:**
```bash
MYSQL_HOST=localhost
MYSQL_PORT=3306
# Don't include passwords!
```

**Error:**
```
Full error message here
```

**Steps to reproduce:**
1. Step one
2. Step two
3. ...

**What I've tried:**
- Solution 1: Result
- Solution 2: Result
```

## Quick Reference

### Common Fixes Checklist

- [ ] MySQL server is running
- [ ] Credentials are correct
- [ ] Database exists and is accessible
- [ ] Environment variables are set
- [ ] Using parameterized queries
- [ ] Pool size < MySQL max_connections
- [ ] Rate limits are appropriate
- [ ] Cache is enabled for performance
- [ ] Using pagination for large results
- [ ] Security features not over-restrictive