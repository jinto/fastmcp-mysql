# FastMCP MySQL Server API Reference

## Table of Contents
1. [Overview](#overview)
2. [Tools](#tools)
   - [mysql_query](#mysql_query)
   - [mysql_health](#mysql_health)
   - [mysql_metrics](#mysql_metrics)
   - [mysql_metrics_prometheus](#mysql_metrics_prometheus)
3. [Data Types](#data-types)
4. [Error Codes](#error-codes)
5. [Examples](#examples)

## Overview

FastMCP MySQL Server provides a set of tools for interacting with MySQL databases through the Model Context Protocol (MCP). All tools are designed with security and performance in mind.

## Tools

### mysql_query

Execute SQL queries against the configured MySQL database with built-in security features.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | Yes | The SQL query to execute. Supports prepared statement placeholders (%s) |
| `params` | array | No | Parameters for prepared statements. Must match the number of placeholders |
| `database` | string | No | Target database name (for multi-database mode, not yet implemented) |

#### Returns

##### Success Response
```json
{
  "success": true,
  "message": "Query executed successfully",
  "data": [...],  // For SELECT queries
  "metadata": {
    "row_count": 10,      // For SELECT queries
    "rows_affected": 1,   // For INSERT/UPDATE/DELETE
    "query_type": "SELECT"
  }
}
```

##### Error Response
```json
{
  "success": false,
  "error": "Error message",
  "message": "Query execution failed"
}
```

#### Security Features
- SQL injection prevention through prepared statements
- Query type validation (DDL operations blocked by default)
- Rate limiting per user/session
- Query filtering (blacklist/whitelist modes)

#### Examples

##### Basic SELECT Query
```python
result = await mysql_query(
    "SELECT id, name, email FROM users WHERE active = 1"
)
```

##### Parameterized Query (Recommended)
```python
result = await mysql_query(
    "SELECT * FROM users WHERE age > %s AND city = %s",
    params=[18, "New York"]
)
```

##### INSERT with Parameters
```python
result = await mysql_query(
    "INSERT INTO users (name, email, age) VALUES (%s, %s, %s)",
    params=["John Doe", "john@example.com", 25]
)
# Note: Requires MYSQL_ALLOW_INSERT=true
```

##### UPDATE with Parameters
```python
result = await mysql_query(
    "UPDATE users SET last_login = NOW() WHERE id = %s",
    params=[123]
)
# Note: Requires MYSQL_ALLOW_UPDATE=true
```

##### DELETE with Parameters
```python
result = await mysql_query(
    "DELETE FROM sessions WHERE expired_at < %s",
    params=["2024-01-01 00:00:00"]
)
# Note: Requires MYSQL_ALLOW_DELETE=true
```

### mysql_health

Check the health status of the MySQL server and its components.

#### Parameters
None

#### Returns

```json
{
  "status": "healthy",  // healthy, degraded, unhealthy
  "timestamp": "2024-01-15T10:30:45.123Z",
  "version": "1.0.0",
  "components": [
    {
      "name": "database",
      "status": "healthy",
      "message": "Database is healthy",
      "details": {
        "pool_metrics": {
          "total_connections": 10,
          "active_connections": 2,
          "idle_connections": 8,
          "utilization_percent": 20.0
        }
      },
      "check_duration_ms": 5.2
    },
    {
      "name": "query_performance",
      "status": "healthy",
      "message": "Query performance is normal",
      "details": {
        "error_rate": 0.5,
        "slow_query_percentage": 2.1
      }
    },
    {
      "name": "cache",
      "status": "degraded",
      "message": "Cache hit rate is below threshold",
      "details": {
        "hit_rate": 45.2,
        "threshold": 50.0
      }
    },
    {
      "name": "error_rates",
      "status": "healthy",
      "message": "Error rates are normal"
    }
  ],
  "summary": {
    "total_components": 4,
    "healthy": 3,
    "degraded": 1,
    "unhealthy": 0
  }
}
```

#### Health Status Definitions
- **healthy**: All checks pass, system operating normally
- **degraded**: Some non-critical issues detected, system operational but may need attention
- **unhealthy**: Critical issues detected, immediate attention required

#### Component Health Thresholds
- **Database**: Connection pool utilization > 90% = degraded
- **Query Performance**: Error rate > 10% = unhealthy, p95 latency > 1s = degraded
- **Cache**: Hit rate < 50% = degraded
- **Error Rates**: > 10 errors/minute = degraded

### mysql_metrics

Get detailed metrics about the MySQL server performance and usage.

#### Parameters
None

#### Returns

```json
{
  "query": {
    "total": 1523,
    "successful": 1498,
    "failed": 25,
    "by_type": {
      "SELECT": 1200,
      "INSERT": 200,
      "UPDATE": 98,
      "DELETE": 25
    },
    "duration_percentiles_ms": {
      "p50": 12.5,
      "p90": 45.2,
      "p95": 78.9,
      "p99": 234.1
    },
    "error_rate": 1.6,
    "slow_queries": [
      {
        "query": "SELECT * FROM large_table",
        "duration_ms": 1523.4,
        "timestamp": "2024-01-15T10:25:30Z"
      }
    ]
  },
  "connection_pool": {
    "total_connections": 10,
    "active_connections": 3,
    "idle_connections": 7,
    "utilization_percent": 30.0,
    "avg_wait_time_ms": 2.3,
    "connection_errors": 0
  },
  "cache": {
    "hits": 4532,
    "misses": 568,
    "hit_rate_percent": 88.9,
    "evictions": 123,
    "current_size": 890,
    "max_size": 1000,
    "utilization_percent": 89.0
  },
  "errors": {
    "by_type": {
      "connection_error": 2,
      "query_error": 23,
      "timeout_error": 5
    },
    "rate_per_minute": 0.5,
    "recent_errors": []
  },
  "custom": {
    "app_version": "1.2.3",
    "environment": "production"
  }
}
```

### mysql_metrics_prometheus

Get metrics in Prometheus exposition format.

#### Parameters
None

#### Returns

Plain text in Prometheus format:
```
# HELP mysql_queries_total Total number of queries
# TYPE mysql_queries_total counter
mysql_queries_total 1523

# HELP mysql_queries_successful_total Total number of successful queries
# TYPE mysql_queries_successful_total counter
mysql_queries_successful_total 1498

# HELP mysql_query_duration_ms Query duration in milliseconds
# TYPE mysql_query_duration_ms summary
mysql_query_duration_ms{quantile="0.5"} 12.5
mysql_query_duration_ms{quantile="0.9"} 45.2
mysql_query_duration_ms{quantile="0.95"} 78.9
mysql_query_duration_ms{quantile="0.99"} 234.1

# HELP mysql_connection_pool_utilization Connection pool utilization percentage
# TYPE mysql_connection_pool_utilization gauge
mysql_connection_pool_utilization 30.0

# HELP mysql_cache_hit_rate Cache hit rate percentage
# TYPE mysql_cache_hit_rate gauge
mysql_cache_hit_rate 88.9
```

## Data Types

### QueryResult
```typescript
interface QueryResult {
  success: boolean;
  message: string;
  data?: any[];  // For SELECT queries
  metadata?: {
    row_count?: number;     // For SELECT
    rows_affected?: number; // For INSERT/UPDATE/DELETE
    query_type: string;
  };
  error?: string;  // Only on failure
}
```

### HealthStatus
```typescript
type HealthStatus = "healthy" | "degraded" | "unhealthy";

interface ComponentHealth {
  name: string;
  status: HealthStatus;
  message: string;
  details?: Record<string, any>;
  check_duration_ms?: number;
}
```

### SecurityContext
```typescript
interface SecurityContext {
  user_id: string;
  ip_address?: string;
  session_id?: string;
}
```

## Error Codes

### Security Errors (4xx)
| Code | Name | Description |
|------|------|-------------|
| 401 | UNAUTHORIZED | Authentication required |
| 403 | FORBIDDEN | Operation not permitted |
| 429 | RATE_LIMITED | Too many requests |
| 440 | SQL_INJECTION_DETECTED | SQL injection attempt detected |
| 441 | QUERY_BLACKLISTED | Query matches blacklist pattern |
| 442 | QUERY_NOT_WHITELISTED | Query doesn't match whitelist |

### Database Errors (5xx)
| Code | Name | Description |
|------|------|-------------|
| 500 | INTERNAL_ERROR | Unexpected server error |
| 502 | CONNECTION_ERROR | Cannot connect to database |
| 503 | POOL_EXHAUSTED | Connection pool exhausted |
| 504 | QUERY_TIMEOUT | Query execution timeout |
| 505 | TRANSACTION_ERROR | Transaction failed |

### Validation Errors (4xx)
| Code | Name | Description |
|------|------|-------------|
| 400 | INVALID_QUERY | Query syntax error |
| 411 | PARAMETER_MISMATCH | Parameter count mismatch |
| 412 | INVALID_PARAMETER | Invalid parameter type/value |
| 413 | QUERY_TOO_LONG | Query exceeds max length |

## Examples

### Basic Usage
```python
from fastmcp_mysql import mysql_query, mysql_health, mysql_metrics

# Check health before querying
health = await mysql_health()
if health["status"] == "unhealthy":
    print("Database is unhealthy, aborting")
    return

# Execute a simple query
result = await mysql_query("SELECT COUNT(*) as total FROM users")
if result["success"]:
    print(f"Total users: {result['data'][0]['total']}")

# Get current metrics
metrics = await mysql_metrics()
print(f"Cache hit rate: {metrics['cache']['hit_rate_percent']}%")
```

### Error Handling
```python
try:
    result = await mysql_query(
        "INSERT INTO audit_log (action, user_id) VALUES (%s, %s)",
        params=["login", user_id]
    )
    
    if not result["success"]:
        # Handle query error
        if "RATE_LIMITED" in result["error"]:
            await asyncio.sleep(60)  # Wait before retry
        elif "SQL_INJECTION" in result["error"]:
            log_security_incident(result["error"])
        else:
            log_error(result["error"])
except Exception as e:
    # Handle connection errors
    log_critical(f"Database connection failed: {e}")
```

### Performance Monitoring
```python
# Monitor query performance
metrics = await mysql_metrics()
p95_latency = metrics["query"]["duration_percentiles_ms"]["p95"]

if p95_latency > 100:  # 100ms threshold
    # Alert on slow queries
    slow_queries = metrics["query"]["slow_queries"]
    for query in slow_queries[:5]:  # Top 5 slow queries
        print(f"Slow query ({query['duration_ms']}ms): {query['query'][:50]}...")
```

### Batch Operations
```python
# Execute multiple inserts efficiently
users = [
    ("Alice", "alice@example.com"),
    ("Bob", "bob@example.com"),
    ("Charlie", "charlie@example.com")
]

for name, email in users:
    result = await mysql_query(
        "INSERT INTO users (name, email) VALUES (%s, %s)",
        params=[name, email]
    )
    if not result["success"]:
        print(f"Failed to insert {name}: {result['error']}")
```

## Best Practices

1. **Always use parameterized queries** to prevent SQL injection
2. **Check health status** before performing critical operations
3. **Monitor metrics** to detect performance issues early
4. **Handle rate limiting** gracefully with exponential backoff
5. **Log security events** for audit compliance
6. **Use appropriate timeouts** for long-running queries
7. **Cache query results** when appropriate
8. **Validate input** before sending to database

## Rate Limiting

The API implements rate limiting to prevent abuse:

- Default: 60 requests per minute (configurable)
- Burst capacity: 10 requests (configurable)
- Rate limit headers are included in responses
- Use exponential backoff when rate limited

## Pagination

For large result sets, implement pagination:

```python
page_size = 100
offset = 0

while True:
    result = await mysql_query(
        "SELECT * FROM large_table LIMIT %s OFFSET %s",
        params=[page_size, offset]
    )
    
    if not result["data"]:
        break
        
    process_batch(result["data"])
    offset += page_size
```

## Transaction Support

Transactions are not yet implemented but planned for future releases. Current workaround:

```python
# Use multiple related queries with proper error handling
try:
    # Debit account
    result1 = await mysql_query(
        "UPDATE accounts SET balance = balance - %s WHERE id = %s",
        params=[amount, from_account]
    )
    
    if result1["success"]:
        # Credit account
        result2 = await mysql_query(
            "UPDATE accounts SET balance = balance + %s WHERE id = %s",
            params=[amount, to_account]
        )
        
        if not result2["success"]:
            # Manual rollback needed
            await mysql_query(
                "UPDATE accounts SET balance = balance + %s WHERE id = %s",
                params=[amount, from_account]
            )
except Exception as e:
    # Handle error
    pass
```