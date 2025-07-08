"""Security configuration examples for FastMCP MySQL Server."""

import asyncio
import os
from typing import Dict, Any
import time


async def security_configuration_example():
    """Demonstrate various security configurations."""
    print("=== Security Configuration Examples ===\n")
    
    # 1. Development environment (balanced security)
    print("1. Development Environment Configuration:")
    dev_config = {
        "MYSQL_HOST": "localhost",
        "MYSQL_USER": "dev_user",
        "MYSQL_PASSWORD": "dev_password",
        "MYSQL_DB": "development",
        
        # Security settings
        "MYSQL_ENABLE_SECURITY": "true",
        "MYSQL_ENABLE_INJECTION_DETECTION": "true",
        "MYSQL_ENABLE_RATE_LIMITING": "true",
        "MYSQL_FILTER_MODE": "blacklist",
        "MYSQL_RATE_LIMIT_RPM": "120",  # Higher limit for development
        "MYSQL_RATE_LIMIT_BURST": "20",
        "MYSQL_LOG_SECURITY_EVENTS": "true",
        "MYSQL_LOG_REJECTED_QUERIES": "true",
        
        # Allow some write operations for testing
        "MYSQL_ALLOW_INSERT": "true",
        "MYSQL_ALLOW_UPDATE": "true",
        "MYSQL_ALLOW_DELETE": "false",  # Still restrict DELETE
    }
    print("   Configuration:", {k: v for k, v in dev_config.items() if k.startswith("MYSQL_") and "PASSWORD" not in k})
    
    # 2. Production environment (maximum security)
    print("\n2. Production Environment Configuration:")
    prod_config = {
        "MYSQL_HOST": "prod-mysql.internal",
        "MYSQL_USER": "app_readonly",
        "MYSQL_PASSWORD": "strong_password",
        "MYSQL_DB": "production",
        
        # Security settings
        "MYSQL_ENABLE_SECURITY": "true",
        "MYSQL_ENABLE_INJECTION_DETECTION": "true",
        "MYSQL_ENABLE_RATE_LIMITING": "true",
        "MYSQL_FILTER_MODE": "combined",  # Both whitelist and blacklist
        "MYSQL_RATE_LIMIT_RPM": "60",
        "MYSQL_RATE_LIMIT_BURST": "10",
        "MYSQL_RATE_LIMIT_ALGORITHM": "token_bucket",
        "MYSQL_MAX_QUERY_LENGTH": "5000",
        "MYSQL_LOG_SECURITY_EVENTS": "true",
        "MYSQL_LOG_REJECTED_QUERIES": "false",  # Reduce log volume
        "MYSQL_AUDIT_ALL_QUERIES": "false",
        
        # No write operations in production
        "MYSQL_ALLOW_INSERT": "false",
        "MYSQL_ALLOW_UPDATE": "false",
        "MYSQL_ALLOW_DELETE": "false",
    }
    print("   Configuration:", {k: v for k, v in prod_config.items() if k.startswith("MYSQL_") and "PASSWORD" not in k})
    
    # 3. High-security environment (financial/healthcare)
    print("\n3. High-Security Environment Configuration:")
    secure_config = {
        "MYSQL_HOST": "secure-mysql.private",
        "MYSQL_USER": "audit_user",
        "MYSQL_PASSWORD": "ultra_secure_password",
        "MYSQL_DB": "sensitive_data",
        
        # Maximum security
        "MYSQL_ENABLE_SECURITY": "true",
        "MYSQL_ENABLE_INJECTION_DETECTION": "true",
        "MYSQL_ENABLE_RATE_LIMITING": "true",
        "MYSQL_FILTER_MODE": "whitelist",  # Only allow specific queries
        "MYSQL_RATE_LIMIT_RPM": "30",  # Very restrictive
        "MYSQL_RATE_LIMIT_BURST": "5",
        "MYSQL_RATE_LIMIT_ALGORITHM": "sliding_window",  # No burst allowed
        "MYSQL_MAX_QUERY_LENGTH": "2000",
        "MYSQL_MAX_PARAMETER_LENGTH": "500",
        "MYSQL_LOG_SECURITY_EVENTS": "true",
        "MYSQL_LOG_REJECTED_QUERIES": "true",
        "MYSQL_AUDIT_ALL_QUERIES": "true",  # Full audit trail
        
        # No write operations
        "MYSQL_ALLOW_INSERT": "false",
        "MYSQL_ALLOW_UPDATE": "false",
        "MYSQL_ALLOW_DELETE": "false",
    }
    print("   Configuration:", {k: v for k, v in secure_config.items() if k.startswith("MYSQL_") and "PASSWORD" not in k})


async def sql_injection_prevention_example():
    """Demonstrate SQL injection prevention."""
    from fastmcp_mysql.server import create_server
    
    print("\n\n=== SQL Injection Prevention Examples ===\n")
    
    # Set up security-enabled environment
    os.environ.update({
        "MYSQL_HOST": "localhost",
        "MYSQL_USER": "root",
        "MYSQL_PASSWORD": "password",
        "MYSQL_DB": "test",
        "MYSQL_ENABLE_SECURITY": "true",
        "MYSQL_ENABLE_INJECTION_DETECTION": "true",
        "MYSQL_LOG_SECURITY_EVENTS": "true",
        "MYSQL_LOG_REJECTED_QUERIES": "true",
    })
    
    server = await create_server()
    
    # Common SQL injection attempts that will be blocked
    injection_attempts = [
        # 1. Classic injection
        ("SELECT * FROM users WHERE id = '1' OR '1'='1'", "Classic OR injection"),
        
        # 2. Union-based injection
        ("SELECT name FROM users WHERE id = 1 UNION SELECT password FROM admin", "UNION injection"),
        
        # 3. Comment-based injection
        ("SELECT * FROM users WHERE name = 'admin'--' AND password = 'anything'", "Comment injection"),
        
        # 4. Time-based blind injection
        ("SELECT * FROM users WHERE id = 1 AND SLEEP(5)", "Time-based injection"),
        
        # 5. Stacked queries
        ("SELECT * FROM users; DROP TABLE users;--", "Stacked query injection"),
        
        # 6. Encoded injection
        ("SELECT * FROM users WHERE id = 0x31204f522031%3d31", "Hex encoded injection"),
    ]
    
    print("Testing common SQL injection patterns:\n")
    for query, description in injection_attempts:
        print(f"{description}:")
        print(f"  Query: {query[:60]}...")
        result = await server.mysql_query(query)
        if not result["success"]:
            print(f"  ✓ Blocked: {result['error']}")
        else:
            print(f"  ✗ Unexpectedly allowed!")
        print()
    
    # Show safe alternative
    print("\nSafe alternative using parameters:")
    print("  Query: SELECT * FROM users WHERE id = %s")
    print("  Params: [1]")
    result = await server.mysql_query(
        "SELECT * FROM information_schema.tables WHERE table_schema = %s LIMIT 1",
        params=["mysql"]
    )
    print(f"  ✓ Allowed: {result['success']}")


async def rate_limiting_example():
    """Demonstrate rate limiting in action."""
    from fastmcp_mysql.server import create_server
    
    print("\n\n=== Rate Limiting Examples ===\n")
    
    # Configure aggressive rate limiting
    os.environ.update({
        "MYSQL_ENABLE_RATE_LIMITING": "true",
        "MYSQL_RATE_LIMIT_RPM": "10",  # Very low for demonstration
        "MYSQL_RATE_LIMIT_BURST": "3",
        "MYSQL_RATE_LIMIT_ALGORITHM": "token_bucket",
    })
    
    server = await create_server()
    
    print("Configuration: 10 requests/minute, burst of 3\n")
    
    # Simulate rapid requests
    print("Sending rapid requests:")
    success_count = 0
    blocked_count = 0
    
    for i in range(15):
        result = await server.mysql_query("SELECT 1 as test")
        
        if result["success"]:
            success_count += 1
            status = "✓ Allowed"
        else:
            blocked_count += 1
            status = "✗ Rate limited" if "rate" in result["error"].lower() else "✗ Error"
        
        print(f"  Request {i+1:2d}: {status}")
        
        # Small delay to show burst behavior
        if i == 3:
            print("  --- Burst capacity exhausted ---")
        
        await asyncio.sleep(0.1)
    
    print(f"\nResults: {success_count} allowed, {blocked_count} blocked")
    
    # Demonstrate waiting for rate limit reset
    print("\nWaiting 6 seconds for partial token refill...")
    await asyncio.sleep(6)
    
    print("Sending another request:")
    result = await server.mysql_query("SELECT 1 as test")
    print(f"  Result: {'✓ Allowed' if result['success'] else '✗ Still limited'}")


async def query_filtering_example():
    """Demonstrate query filtering (whitelist/blacklist)."""
    from fastmcp_mysql.server import create_server
    
    print("\n\n=== Query Filtering Examples ===\n")
    
    # 1. Blacklist mode (default)
    print("1. Blacklist Mode (blocks dangerous operations):\n")
    
    os.environ.update({
        "MYSQL_ENABLE_SECURITY": "true",
        "MYSQL_FILTER_MODE": "blacklist",
    })
    
    server = await create_server()
    
    blacklist_tests = [
        ("SELECT * FROM users", "Normal SELECT", True),
        ("SELECT * FROM information_schema.tables", "System table access", False),
        ("SELECT LOAD_FILE('/etc/passwd')", "File operation", False),
        ("SELECT * INTO OUTFILE '/tmp/data.csv' FROM users", "File write", False),
        ("CREATE USER 'hacker'@'%'", "User management", False),
        ("GRANT ALL ON *.* TO 'hacker'@'%'", "Permission change", False),
    ]
    
    for query, description, should_pass in blacklist_tests:
        result = await server.mysql_query(query)
        status = "✓ Allowed" if result["success"] else "✗ Blocked"
        expected = "✓" if should_pass == result["success"] else "✗"
        print(f"  {description}: {status} {expected}")
    
    # 2. Whitelist mode (only allows specific patterns)
    print("\n2. Whitelist Mode (only allows specific patterns):\n")
    
    # Note: In real implementation, whitelist patterns would be configured
    print("  (Whitelist configuration would allow only specific query patterns)")
    print("  Example whitelist patterns:")
    print("  - ^SELECT .* FROM users WHERE id = %s$")
    print("  - ^SELECT .* FROM products WHERE category = %s$")
    print("  - ^INSERT INTO audit_log .* VALUES \\(%s, %s\\)$")


async def security_logging_example():
    """Demonstrate security event logging."""
    from fastmcp_mysql.server_enhanced import create_enhanced_server
    import json
    
    print("\n\n=== Security Logging Examples ===\n")
    
    os.environ.update({
        "MYSQL_LOG_LEVEL": "INFO",
        "MYSQL_LOG_SECURITY_EVENTS": "true",
        "MYSQL_LOG_REJECTED_QUERIES": "true",
        "MYSQL_ENABLE_FILE_LOGGING": "true",
        "MYSQL_LOG_DIR": "/tmp/fastmcp-mysql-security",
    })
    
    server = await create_enhanced_server()
    
    # Generate various security events
    security_events = [
        # SQL injection attempt
        ("SELECT * FROM users WHERE id = '1' OR '1'='1'", "SQL injection"),
        # Rate limit test (send multiple requests)
        ("SELECT 1", "Rate limiting"),
        # Blacklisted operation
        ("DROP TABLE users", "Blacklisted query"),
        # Parameter validation
        ("SELECT * FROM users WHERE id = %s", "Missing parameters"),
    ]
    
    print("Generating security events for logging:\n")
    
    for query, event_type in security_events:
        print(f"{event_type}:")
        
        if event_type == "Rate limiting":
            # Send multiple requests to trigger rate limit
            for i in range(5):
                await server.mysql_query(query)
        elif event_type == "Missing parameters":
            result = await server.mysql_query(query)  # No params provided
        else:
            result = await server.mysql_query(query)
        
        print(f"  Query: {query[:50]}...")
        print(f"  Event logged: ✓\n")
    
    # Show sample log format
    print("Sample security log entry format:")
    sample_log = {
        "timestamp": "2024-01-15T10:30:45.123Z",
        "level": "WARNING",
        "message": "Security event: injection_detected",
        "event_type": "injection_detected",
        "details": {
            "query": "SELECT * FROM users WHERE...",
            "threats": ["SQL injection detected"],
            "user": "user_123",
            "ip_address": "192.168.1.100"
        }
    }
    print(json.dumps(sample_log, indent=2))


async def security_metrics_example():
    """Show security-related metrics."""
    from fastmcp_mysql.server_enhanced import create_enhanced_server
    
    print("\n\n=== Security Metrics Examples ===\n")
    
    server = await create_enhanced_server()
    
    # Generate some security events
    print("Generating security events...\n")
    
    # Some legitimate queries
    for i in range(5):
        await server.mysql_query("SELECT 1 as num")
    
    # Some that will be blocked
    await server.mysql_query("SELECT * FROM users WHERE id = '1' OR '1'='1'")
    await server.mysql_query("DROP TABLE users")
    await server.mysql_query("SELECT SLEEP(10)")
    
    # Get metrics
    metrics = await server.mysql_metrics()
    
    print("Security Metrics:")
    print(f"  Total queries: {metrics['query']['total']}")
    print(f"  Failed queries: {metrics['query']['failed']}")
    print(f"  Error rate: {metrics['query']['error_rate']:.1f}%")
    
    if 'errors' in metrics:
        print(f"\n  Error breakdown:")
        for error_type, count in metrics['errors']['by_type'].items():
            print(f"    - {error_type}: {count}")
    
    # Health check will show if security issues affect health
    health = await server.mysql_health()
    print(f"\n  System health: {health['status']}")
    for component in health['components']:
        if component['status'] != 'healthy':
            print(f"    - {component['name']}: {component['status']} - {component['message']}")


async def main():
    """Run all security examples."""
    print("\n" + "="*60)
    print("FastMCP MySQL Server - Security Examples")
    print("="*60 + "\n")
    
    try:
        await security_configuration_example()
        await sql_injection_prevention_example()
        await rate_limiting_example()
        await query_filtering_example()
        await security_logging_example()
        await security_metrics_example()
        
    except Exception as e:
        print(f"\nError running examples: {e}")
    
    print("\n" + "="*60)
    print("Security examples completed!")
    print("="*60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())