# Frequently Asked Questions (FAQ)

## Table of Contents

1. [General Questions](#general-questions)
2. [Installation & Setup](#installation--setup)
3. [Configuration](#configuration)
4. [Security](#security)
5. [Performance](#performance)
6. [Troubleshooting](#troubleshooting)
7. [Development](#development)

## General Questions

### What is FastMCP MySQL Server?

FastMCP MySQL Server is a secure MySQL database interface for Large Language Models (LLMs) using the Model Context Protocol (MCP). It provides controlled access to MySQL databases with built-in security features, making it safe to use with AI assistants like Claude.

### How is it different from direct database access?

Unlike direct database access, FastMCP MySQL Server provides:
- **Security layers**: SQL injection prevention, query filtering, rate limiting
- **Controlled permissions**: Read-only by default, optional write access
- **Monitoring**: Built-in health checks and metrics
- **LLM optimization**: Structured responses suitable for AI processing

### What databases are supported?

Currently, only MySQL 5.7+ and MariaDB 10.2+ are supported. MySQL 8.0+ is recommended for best performance and features.

### Is it production-ready?

Yes, version 1.0.0 is production-ready with:
- Comprehensive security features
- 85%+ test coverage
- Performance optimization
- Production-grade logging and monitoring

## Installation & Setup

### How do I install FastMCP MySQL Server?

The easiest way is using `uvx`:
```bash
uvx fastmcp-mysql
```

Or install with pip:
```bash
pip install fastmcp-mysql
```

### What are the system requirements?

- Python 3.10 or higher
- MySQL 5.7+ (8.0+ recommended)
- 512MB RAM minimum (1GB+ recommended)
- Network access to MySQL server

### How do I set it up with Claude Desktop?

Add to your Claude Desktop configuration file:
```json
{
  "mcpServers": {
    "mysql": {
      "command": "uvx",
      "args": ["fastmcp-mysql"],
      "env": {
        "MYSQL_HOST": "localhost",
        "MYSQL_USER": "your_user",
        "MYSQL_PASSWORD": "your_password",
        "MYSQL_DB": "your_database"
      }
    }
  }
}
```

## Configuration

### What environment variables are required?

Required:
- `MYSQL_USER`: Database username
- `MYSQL_PASSWORD`: Database password
- `MYSQL_DB`: Database name

Optional but recommended:
- `MYSQL_HOST`: Database host (default: "127.0.0.1")
- `MYSQL_PORT`: Database port (default: "3306")

### How do I enable write operations?

Write operations are disabled by default. Enable them individually:
```bash
MYSQL_ALLOW_INSERT=true  # Enable INSERT
MYSQL_ALLOW_UPDATE=true  # Enable UPDATE
MYSQL_ALLOW_DELETE=true  # Enable DELETE
```

### Can I connect to multiple databases?

Multi-database mode is planned for version 1.1.0. Currently, you can:
1. Run multiple server instances with different configurations
2. Switch databases using fully qualified table names

### How do I configure connection pooling?

```bash
MYSQL_POOL_SIZE=10          # Number of connections (default: 10)
MYSQL_QUERY_TIMEOUT=30000   # Query timeout in ms (default: 30 seconds)
```

## Security

### How does SQL injection prevention work?

Multiple layers of protection:
1. **Prepared statements**: All queries use parameterized statements
2. **Pattern detection**: Advanced detection of injection attempts
3. **Query validation**: Syntax and structure validation
4. **Encoding detection**: Catches URL/Unicode/Hex encoded attacks

### What is the difference between blacklist and whitelist modes?

- **Blacklist mode** (default): Blocks known dangerous patterns
  - Good for development and general use
  - Blocks DDL, system tables, file operations
  
- **Whitelist mode**: Only allows specific query patterns
  - Best for production with known query patterns
  - Maximum security but requires configuration

- **Combined mode**: Uses both blacklist and whitelist
  - Balanced approach for production

### How do I handle rate limiting?

Configure rate limits based on your needs:
```bash
MYSQL_RATE_LIMIT_RPM=60      # Requests per minute
MYSQL_RATE_LIMIT_BURST=10    # Burst capacity
MYSQL_RATE_LIMIT_ALGORITHM=token_bucket  # or sliding_window, fixed_window
```

### Are queries logged?

Security events are logged by default. Configure with:
```bash
MYSQL_LOG_SECURITY_EVENTS=true   # Log security violations
MYSQL_LOG_REJECTED_QUERIES=true  # Log blocked queries
MYSQL_AUDIT_ALL_QUERIES=false   # Full audit (performance impact)
```

## Performance

### How can I improve query performance?

1. **Enable caching**:
   ```bash
   MYSQL_CACHE_ENABLED=true
   MYSQL_CACHE_MAX_SIZE=1000
   MYSQL_CACHE_TTL=60000  # 60 seconds
   ```

2. **Optimize connection pool**:
   ```bash
   MYSQL_POOL_SIZE=20  # Increase for high concurrency
   ```

3. **Use pagination** for large result sets
4. **Create appropriate indexes** in your database

### What are the performance benchmarks?

Typical performance metrics:
- Simple SELECT: < 10ms
- Complex queries: < 100ms
- Connection pool overhead: < 1ms
- Security validation: < 0.5ms

### How do I monitor performance?

Use the built-in metrics:
```python
metrics = await mysql_metrics()
print(f"p95 latency: {metrics['query']['duration_percentiles_ms']['p95']}ms")
```

### Does caching work with write operations?

Yes, the cache is automatically invalidated based on the configured mode:
- `aggressive`: Clears all cache on any write
- `conservative`: Only expires based on TTL
- `targeted`: Invalidates specific table caches

## Troubleshooting

### Why am I getting "Connection refused" errors?

Check:
1. MySQL server is running
2. Host and port are correct
3. Firewall allows connections
4. MySQL user has proper permissions

### Why are my queries being rejected?

Common reasons:
1. **Security blocks**: Check logs for SQL injection or blacklist matches
2. **Rate limiting**: You've exceeded the configured rate limit
3. **Permissions**: Write operations not enabled
4. **Syntax errors**: Invalid SQL syntax

### How do I debug issues?

1. Enable debug logging:
   ```bash
   MYSQL_LOG_LEVEL=DEBUG
   ```

2. Check security logs for blocked queries
3. Use health check to verify connectivity:
   ```python
   health = await mysql_health()
   ```

### Why is the connection pool exhausted?

This happens when all connections are in use. Solutions:
1. Increase pool size: `MYSQL_POOL_SIZE=20`
2. Reduce query timeout: `MYSQL_QUERY_TIMEOUT=10000`
3. Check for long-running queries
4. Ensure connections are properly released

## Development

### How do I contribute?

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines. Quick steps:
1. Fork the repository
2. Create a feature branch
3. Write tests first (TDD)
4. Submit a pull request

### How do I run tests?

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=fastmcp_mysql

# Run specific test
uv run pytest tests/unit/test_connection.py
```

### What's the architecture pattern?

We follow Clean Architecture:
- **Interfaces**: Abstract contracts
- **Use cases**: Business logic
- **Infrastructure**: Database, external services
- **Dependency injection**: Loose coupling

### How do I add a new security feature?

1. Define interface in `security/interfaces/`
2. Implement in appropriate module
3. Add to `SecurityManager`
4. Write comprehensive tests
5. Update documentation

## More Questions?

If your question isn't answered here:
1. Check the [documentation](docs/)
2. Search [existing issues](https://github.com/jinto/fastmcp-mysql/issues)
3. Open a [new issue](https://github.com/jinto/fastmcp-mysql/issues/new)
4. Join our [discussions](https://github.com/jinto/fastmcp-mysql/discussions)