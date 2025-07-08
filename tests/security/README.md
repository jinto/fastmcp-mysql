# Security Testing Guide

## Overview

This directory contains comprehensive security tests for the FastMCP MySQL server. The tests follow TDD principles and cover:

1. SQL Injection Prevention
2. Query Filtering (Whitelist/Blacklist)
3. Rate Limiting
4. Integration Testing

## Test Structure

```
tests/security/
├── conftest.py                    # Shared fixtures and test data
├── test_sql_injection.py          # SQL injection prevention tests
├── test_query_filtering.py        # Query whitelist/blacklist tests
├── test_rate_limiting.py          # Rate limiting tests
├── test_security_integration.py   # Integration tests
└── test_security_architecture.py  # Architecture and interface tests
```

## Running Security Tests

```bash
# Run all security tests
pytest tests/security/

# Run specific test file
pytest tests/security/test_sql_injection.py

# Run with coverage
pytest tests/security/ --cov=fastmcp_mysql.security

# Run with verbose output
pytest tests/security/ -v

# Run specific test case
pytest tests/security/test_sql_injection.py::TestSQLInjectionPrevention::test_detect_sql_injection_attempts
```

## Implementation Guide

### 1. SQL Injection Prevention

Based on the tests in `test_sql_injection.py`, implement:

```python
# src/fastmcp_mysql/security/sql_injection.py
class SqlInjectionValidator:
    def validate_query(self, query: str) -> bool:
        # Check for multiple statements
        # Validate query structure
        # Detect common injection patterns
        pass
    
    def sanitize_parameters(self, params: list) -> list:
        # Escape special characters
        # Validate parameter types
        pass
```

### 2. Query Filtering

Based on the tests in `test_query_filtering.py`, implement:

```python
# src/fastmcp_mysql/security/query_filter.py
class QueryFilter:
    def __init__(self, config: Dict[str, Any]):
        self.whitelist_patterns = config.get("whitelist_patterns", [])
        self.blacklist_patterns = config.get("blacklist_patterns", [])
        # ... other configuration
    
    def is_allowed(self, query: str) -> tuple[bool, str]:
        # Check whitelist/blacklist patterns
        # Validate table access
        # Check operation types
        pass
```

### 3. Rate Limiting

Based on the tests in `test_rate_limiting.py`, implement:

```python
# src/fastmcp_mysql/security/rate_limiter.py
class RateLimiter:
    def __init__(self, config: Dict[str, Any]):
        self.max_requests_per_minute = config.get("max_requests_per_minute", 60)
        # ... other configuration
    
    async def check_rate_limit(self, client_id: str) -> tuple[bool, str]:
        # Check request counts
        # Implement sliding window
        # Handle burst requests
        pass
```

### 4. Security Manager

Integrate all components:

```python
# src/fastmcp_mysql/security/manager.py
class SecurityManager:
    def __init__(self, config: Dict[str, Any]):
        self.sql_validator = SqlInjectionValidator(config["sql_injection"])
        self.query_filter = QueryFilter(config["query_filter"])
        self.rate_limiter = RateLimiter(config["rate_limiting"])
    
    async def validate_request(
        self,
        query: str,
        params: Optional[list] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> tuple[bool, str]:
        # Run through all security checks
        pass
```

## Test Data

The `conftest.py` file provides comprehensive test data:

- **SQL_INJECTION_PAYLOADS**: Common SQL injection attack patterns
- **SAFE_QUERIES**: Examples of legitimate queries
- **EDGE_CASE_QUERIES**: Queries with unusual formatting

## Mocking Strategy

### Connection Manager Mock

```python
@pytest.fixture
def mock_connection_manager():
    manager = MagicMock(spec=ConnectionManager)
    manager.execute = AsyncMock(return_value=[])
    return manager
```

### Rate Limiter Mock

```python
@pytest.fixture
def mock_rate_limiter():
    limiter = MagicMock()
    limiter.check_rate_limit = AsyncMock(return_value=(True, "OK"))
    return limiter
```

## Edge Cases to Test

1. **Encoded Attacks**: Hex, URL, Base64 encoded payloads
2. **Case Variations**: Mixed case SQL keywords
3. **Unicode Attacks**: Unicode normalization exploits
4. **Time-based Attacks**: SLEEP, BENCHMARK functions
5. **Second-order Injection**: Stored injection attempts

## Performance Testing

The tests include performance benchmarks:

- Security overhead should be < 50% of baseline
- Rate limiter should handle 1000 checks in < 100ms
- Query filter with 1000 rules should validate in < 0.1ms

## Security Metrics

Track these metrics during implementation:

- `security.requests.total`: Total requests
- `security.requests.blocked`: Blocked requests by type
- `security.validation.duration`: Validation time
- `security.sql_injection.attempts`: Injection attempts

## Integration Points

When integrating with the main query executor:

1. Add security validation before query execution
2. Include security context in all operations
3. Log security events for audit trail
4. Return appropriate error responses

## Next Steps

1. Run the tests to see failures (TDD red phase)
2. Implement security modules to make tests pass (green phase)
3. Refactor and optimize implementation (refactor phase)
4. Add additional tests for new edge cases discovered