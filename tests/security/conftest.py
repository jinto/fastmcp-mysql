"""Common fixtures and test data for security tests."""

import pytest
from typing import List

from fastmcp_mysql.security import SecuritySettings, SecurityManager
from fastmcp_mysql.security.config import FilterMode, RateLimitAlgorithm


@pytest.fixture
def security_settings():
    """Default security settings for tests."""
    return SecuritySettings(
        enable_injection_detection=True,
        enable_rate_limiting=True,
        filter_mode=FilterMode.BLACKLIST,
        rate_limit_requests_per_minute=60,
        rate_limit_burst_size=10,
    )


@pytest.fixture
def sql_injection_payloads() -> List[str]:
    """Common SQL injection test payloads."""
    return [
        # Classic injection
        "admin' OR '1'='1",
        "admin'--",
        "admin' OR 1=1--",
        "' OR '1'='1' --",
        "admin'; DROP TABLE users--",
        
        # Union-based injection
        "' UNION SELECT * FROM information_schema.tables--",
        "' UNION SELECT username, password FROM users--",
        "1' UNION ALL SELECT NULL,NULL,NULL--",
        
        # Time-based blind injection
        "1' AND SLEEP(5)--",
        "1'; WAITFOR DELAY '00:00:05'--",
        "1' AND BENCHMARK(5000000,SHA1(1))--",
        
        # Boolean-based blind injection
        "1' AND 1=1--",
        "1' AND 1=2--",
        "1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>65--",
        
        # Error-based injection
        "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT password FROM users LIMIT 1),FLOOR(RAND(0)*2))x FROM users GROUP BY x)a)--",
        
        # Stacked queries
        "1'; INSERT INTO users VALUES ('hacker', 'password')--",
        "1'; UPDATE users SET password='hacked' WHERE username='admin'--",
        
        # Comment variations
        "admin'/*comment*/OR/*comment*/'1'='1",
        "admin'#comment\nOR '1'='1",
        
        # Encoding attempts
        "admin%27%20OR%20%271%27%3D%271",  # URL encoded
        "admin\\' OR \\'1\\'=\\'1",  # Escaped quotes
        
        # Advanced techniques
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users LIMIT 1)))--",
        "1' PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users LIMIT 1))),1)--",
    ]


@pytest.fixture
def safe_queries() -> List[str]:
    """Safe SQL queries that should pass validation."""
    return [
        "SELECT * FROM users WHERE id = %s",
        "SELECT name, email FROM customers WHERE status = %s AND created_at > %s",
        "INSERT INTO logs (message, level) VALUES (%s, %s)",
        "UPDATE products SET price = %s WHERE id = %s",
        "DELETE FROM sessions WHERE expired_at < %s",
        "SELECT COUNT(*) FROM orders WHERE user_id = %s",
        "SELECT * FROM products WHERE name LIKE %s",
    ]


@pytest.fixture
def dangerous_queries() -> List[str]:
    """Queries that should be blocked by blacklist."""
    return [
        # System database access
        "SELECT * FROM information_schema.tables",
        "SELECT * FROM mysql.user",
        "SELECT * FROM performance_schema.threads",
        
        # File operations
        "SELECT LOAD_FILE('/etc/passwd')",
        "SELECT * INTO OUTFILE '/tmp/data.txt' FROM users",
        "SELECT * INTO DUMPFILE '/tmp/data.bin' FROM users",
        
        # User management
        "CREATE USER 'hacker'@'%' IDENTIFIED BY 'password'",
        "DROP USER 'admin'@'localhost'",
        "GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%'",
        "REVOKE SELECT ON mydb.* FROM 'user'@'host'",
        
        # Dangerous functions
        "SELECT SLEEP(10)",
        "SELECT BENCHMARK(1000000, MD5('test'))",
        "SELECT GET_LOCK('mylock', 10)",
        
        # Stored procedures
        "CALL dangerous_procedure()",
        "EXECUTE prepared_stmt",
    ]


@pytest.fixture
def test_parameters() -> dict:
    """Test parameters for injection testing."""
    return {
        "safe": [
            ("john_doe",),
            (123,),
            ("john@example.com",),
            ("2024-01-01",),
            (True,),
            (None,),
            ("O'Brien",),  # Legitimate apostrophe
        ],
        "dangerous": [
            ("admin' OR '1'='1",),
            ("'; DROP TABLE users--",),
            ("' UNION SELECT * FROM passwords--",),
            ("1' AND SLEEP(5)--",),  # Time-based injection
            ("' OR 1=1--",),  # Classic injection
        ]
    }