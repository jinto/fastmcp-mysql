"""Pytest configuration and fixtures for security tests."""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, List, Any

from fastmcp_mysql.connection import ConnectionManager


# Test Data Sets
SQL_INJECTION_PAYLOADS = [
    # Classic SQL injection
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin'--",
    "admin' #",
    "admin'/*",
    
    # Union-based
    "' UNION SELECT * FROM users--",
    "' UNION SELECT NULL, username, password FROM users--",
    "1' UNION ALL SELECT NULL,NULL,NULL--",
    
    # Stacked queries
    "'; DROP TABLE users; --",
    "'; DELETE FROM logs; --",
    "1'; UPDATE users SET admin=1; --",
    
    # Time-based blind
    "1' AND SLEEP(5)--",
    "1' AND BENCHMARK(1000000,MD5('A'))--",
    "1' WAITFOR DELAY '00:00:05'--",
    
    # Boolean-based blind
    "1' AND 1=1--",
    "1' AND 1=2--",
    "1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
    
    # Out-of-band
    "1' AND (SELECT LOAD_FILE('/etc/passwd'))--",
    "1' UNION SELECT 1,2,3 INTO OUTFILE '/tmp/test.txt'--",
    
    # Second-order injection
    "admin'); INSERT INTO logs VALUES ('Injected'); --",
    
    # NoSQL injection patterns (for completeness)
    "{'$ne': ''}",
    "{'$gt': ''}",
]

SAFE_QUERIES = [
    # Basic SELECT
    "SELECT * FROM users",
    "SELECT id, name FROM users WHERE id = %s",
    "SELECT COUNT(*) FROM orders WHERE status = %s",
    
    # Joins
    "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id",
    
    # Aggregations
    "SELECT status, COUNT(*) FROM orders GROUP BY status",
    "SELECT AVG(total) FROM orders WHERE created_at > %s",
    
    # Subqueries
    "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders WHERE total > %s)",
    
    # CTEs
    "WITH active_users AS (SELECT * FROM users WHERE active = 1) SELECT * FROM active_users",
]

EDGE_CASE_QUERIES = [
    # Case variations
    "SeLeCt * FrOm users",
    "SELECT\t*\nFROM\tusers",
    
    # Comments
    "SELECT /* comment */ * FROM users",
    "SELECT * FROM users -- comment",
    
    # Complex formatting
    "SELECT\n    id,\n    name\nFROM\n    users\nWHERE\n    id = %s",
    
    # Unicode
    "SELECT * FROM users WHERE name = N'Unicode: 你好'",
]


# Fixtures
@pytest.fixture
def mock_connection_manager():
    """Create a mock connection manager for testing."""
    manager = MagicMock(spec=ConnectionManager)
    manager.execute = AsyncMock(return_value=[])
    manager.is_connected = MagicMock(return_value=True)
    return manager


@pytest.fixture
def sql_injection_payloads():
    """Provide SQL injection test payloads."""
    return SQL_INJECTION_PAYLOADS


@pytest.fixture
def safe_queries():
    """Provide safe query examples."""
    return SAFE_QUERIES


@pytest.fixture
def edge_case_queries():
    """Provide edge case queries."""
    return EDGE_CASE_QUERIES


@pytest.fixture
def security_config():
    """Provide default security configuration."""
    return {
        "sql_injection": {
            "enabled": True,
            "strict_mode": True,
        },
        "query_filter": {
            "enabled": True,
            "whitelist_tables": {"users", "orders", "products"},
            "blacklist_patterns": [r".*information_schema.*", r".*LOAD_FILE.*"],
        },
        "rate_limiting": {
            "enabled": True,
            "max_requests_per_minute": 60,
            "max_concurrent_queries": 10,
        },
    }


@pytest.fixture
async def rate_limit_simulator():
    """Simulate rate limiting scenarios."""
    class RateLimitSimulator:
        def __init__(self):
            self.request_counts = {}
        
        async def simulate_burst(self, client_id: str, count: int):
            """Simulate burst of requests."""
            for i in range(count):
                self.request_counts[client_id] = self.request_counts.get(client_id, 0) + 1
                await asyncio.sleep(0.001)  # Small delay
        
        async def simulate_sustained_load(self, client_id: str, rps: int, duration: int):
            """Simulate sustained load."""
            delay = 1.0 / rps
            end_time = asyncio.get_event_loop().time() + duration
            
            while asyncio.get_event_loop().time() < end_time:
                self.request_counts[client_id] = self.request_counts.get(client_id, 0) + 1
                await asyncio.sleep(delay)
        
        def get_count(self, client_id: str) -> int:
            """Get request count for client."""
            return self.request_counts.get(client_id, 0)
    
    return RateLimitSimulator()


@pytest.fixture
def mock_audit_logger():
    """Mock audit logger for testing."""
    logger = MagicMock()
    logger.log_query = MagicMock()
    logger.log_security_event = MagicMock()
    logger.log_error = MagicMock()
    return logger


@pytest.fixture
def attack_scenarios():
    """Provide comprehensive attack scenarios."""
    return [
        {
            "name": "Basic SQL Injection",
            "query": "SELECT * FROM users WHERE id = '1' OR '1'='1'",
            "expected_blocked": True,
            "reason": "sql_injection"
        },
        {
            "name": "Encoded Injection",
            "query": "SELECT * FROM users WHERE id = 0x31204f5220313d31",
            "expected_blocked": True,
            "reason": "encoded_injection"
        },
        {
            "name": "Time-based Blind",
            "query": "SELECT * FROM users WHERE id = 1 AND SLEEP(5)",
            "expected_blocked": True,
            "reason": "dangerous_function"
        },
        {
            "name": "Information Schema Access",
            "query": "SELECT * FROM information_schema.tables",
            "expected_blocked": True,
            "reason": "blacklist_pattern"
        },
        {
            "name": "File System Access",
            "query": "SELECT LOAD_FILE('/etc/passwd')",
            "expected_blocked": True,
            "reason": "dangerous_function"
        },
    ]


@pytest.fixture
async def performance_monitor():
    """Monitor performance during tests."""
    class PerformanceMonitor:
        def __init__(self):
            self.measurements = []
        
        async def measure(self, name: str, func, *args, **kwargs):
            """Measure execution time of a function."""
            import time
            start = time.time()
            result = await func(*args, **kwargs)
            duration = time.time() - start
            
            self.measurements.append({
                "name": name,
                "duration": duration,
                "timestamp": start
            })
            
            return result
        
        def get_stats(self):
            """Get performance statistics."""
            if not self.measurements:
                return {}
            
            durations = [m["duration"] for m in self.measurements]
            return {
                "count": len(durations),
                "total": sum(durations),
                "average": sum(durations) / len(durations),
                "min": min(durations),
                "max": max(durations),
            }
    
    return PerformanceMonitor()


# Helper functions for tests
def create_mock_security_context(
    client_id: str = "test_client",
    tenant_id: str = None,
    ip_address: str = "127.0.0.1"
) -> Dict[str, Any]:
    """Create a mock security context."""
    return {
        "client_id": client_id,
        "tenant_id": tenant_id,
        "ip_address": ip_address,
        "request_id": f"req-{client_id}-123",
        "timestamp": "2024-01-01T00:00:00Z",
    }


def assert_security_event_logged(mock_logger, event_type: str, **expected_fields):
    """Assert that a security event was logged with expected fields."""
    mock_logger.log_security_event.assert_called()
    
    # Find the matching call
    for call in mock_logger.log_security_event.call_args_list:
        args, kwargs = call
        if args[0] == event_type:
            for field, expected_value in expected_fields.items():
                assert kwargs.get(field) == expected_value
            return
    
    raise AssertionError(f"Security event '{event_type}' not logged with expected fields")


# Async test utilities
async def simulate_concurrent_requests(
    query_func,
    num_clients: int,
    queries_per_client: int,
    delay_between_queries: float = 0
) -> List[Dict[str, Any]]:
    """Simulate concurrent requests from multiple clients."""
    async def client_task(client_id: str):
        results = []
        for i in range(queries_per_client):
            result = await query_func(
                f"SELECT * FROM users WHERE id = {i}",
                client_id=client_id
            )
            results.append(result)
            if delay_between_queries > 0:
                await asyncio.sleep(delay_between_queries)
        return results
    
    tasks = []
    for i in range(num_clients):
        task = client_task(f"client_{i}")
        tasks.append(task)
    
    all_results = await asyncio.gather(*tasks)
    return all_results