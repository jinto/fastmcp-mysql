"""Tests for SQL injection prevention."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from fastmcp_mysql.tools.query import QueryValidator, QueryExecutor, mysql_query
from fastmcp_mysql.connection import ConnectionManager


class TestSQLInjectionPrevention:
    """Test SQL injection prevention mechanisms."""

    @pytest.fixture
    def validator(self):
        """Create a validator with all operations allowed."""
        return QueryValidator(
            allow_insert=True,
            allow_update=True,
            allow_delete=True
        )

    @pytest.fixture
    def mock_connection_manager(self):
        """Create a mock connection manager."""
        manager = MagicMock(spec=ConnectionManager)
        manager.execute = AsyncMock(return_value=[])
        return manager

    @pytest.fixture
    def executor(self, mock_connection_manager, validator):
        """Create a query executor."""
        return QueryExecutor(mock_connection_manager, validator)

    # Test Case 1: Basic SQL Injection Attempts
    @pytest.mark.parametrize("malicious_query", [
        # Classic SQL injection
        "SELECT * FROM users WHERE id = 1 OR 1=1",
        "SELECT * FROM users WHERE name = '' OR '1'='1'",
        # Union-based injection
        "SELECT * FROM users WHERE id = 1 UNION SELECT * FROM passwords",
        # Comment-based injection
        "SELECT * FROM users WHERE id = 1--",
        "SELECT * FROM users WHERE id = 1/*comment*/",
        # Stacked queries
        "SELECT * FROM users; DROP TABLE users;",
        "UPDATE users SET admin=1 WHERE id=1; DELETE FROM logs;",
        # Time-based blind injection
        "SELECT * FROM users WHERE id = 1 AND SLEEP(5)",
        "SELECT * FROM users WHERE id = 1 AND BENCHMARK(1000000,SHA1('test'))",
        # Boolean-based blind injection
        "SELECT * FROM users WHERE id = 1 AND 1=1",
        "SELECT * FROM users WHERE id = 1 AND 1=2",
    ])
    async def test_detect_sql_injection_attempts(self, executor, malicious_query):
        """Test detection of common SQL injection patterns."""
        # For now, test that multi-statement queries are blocked
        if ";" in malicious_query and malicious_query.strip().count(";") > 0:
            with pytest.raises(ValueError, match="Multiple statements detected"):
                await executor.execute(malicious_query)

    # Test Case 2: Parameterized Query Safety
    @pytest.mark.parametrize("query,params,expected_safe", [
        # Safe parameterized queries
        ("SELECT * FROM users WHERE id = %s", [1], True),
        ("SELECT * FROM users WHERE name = %s AND age > %s", ["John", 18], True),
        ("INSERT INTO users (name, email) VALUES (%s, %s)", ["Alice", "alice@example.com"], True),
        # Unsafe string concatenation (should be detected in future)
        ("SELECT * FROM users WHERE id = " + str(1), None, False),
    ])
    async def test_parameterized_query_validation(self, executor, query, params, expected_safe):
        """Test that parameterized queries are properly validated."""
        if expected_safe:
            # Should execute without error
            result = await executor.execute(query, params)
            assert result is not None
        else:
            # In future implementation, should detect unsafe queries
            pass

    # Test Case 3: Input Sanitization
    @pytest.mark.parametrize("input_value,expected_sanitized", [
        # Special characters that should be escaped
        ("'; DROP TABLE users; --", "\\'; DROP TABLE users; --"),
        ('"; DELETE FROM logs; --', '\\"\\; DELETE FROM logs\\; --'),
        ("Robert'); DROP TABLE students;--", "Robert\\')\\; DROP TABLE students\\;--"),
        # Null byte injection
        ("admin\x00", "admin"),
        # Unicode tricks
        ("admin‮⁦ ⁩⁦", "admin"),
    ])
    def test_input_sanitization(self, input_value, expected_sanitized):
        """Test that dangerous input is properly sanitized."""
        # This will be implemented in the security module
        # from fastmcp_mysql.security.sanitizer import sanitize_input
        # assert sanitize_input(input_value) == expected_sanitized
        pass

    # Test Case 4: Query Type Restrictions
    @pytest.mark.parametrize("query,should_block", [
        # DDL operations should always be blocked
        ("CREATE TABLE hack (id INT)", True),
        ("DROP TABLE users", True),
        ("ALTER TABLE users ADD COLUMN admin BOOLEAN", True),
        ("TRUNCATE TABLE logs", True),
        # DML operations depend on permissions
        ("INSERT INTO users VALUES (1, 'admin')", False),  # Depends on allow_insert
        ("UPDATE users SET admin=1", False),  # Depends on allow_update
        ("DELETE FROM users", False),  # Depends on allow_delete
    ])
    async def test_query_type_restrictions(self, executor, query, should_block):
        """Test that certain query types are properly restricted."""
        if should_block and query.strip().split()[0].upper() in ["CREATE", "DROP", "ALTER", "TRUNCATE"]:
            with pytest.raises(ValueError, match="DDL operations are not allowed"):
                await executor.execute(query)
        else:
            # Should depend on permissions
            result = await executor.execute(query)
            assert result is not None

    # Test Case 5: Encoded Injection Attempts
    @pytest.mark.parametrize("encoded_query", [
        # Hex encoding
        "SELECT * FROM users WHERE id = 0x31204f5220313d31",  # "1 OR 1=1" in hex
        # URL encoding
        "SELECT * FROM users WHERE name = 'admin%27%20OR%20%271%27%3D%271'",
        # Base64 injection attempts
        "SELECT * FROM users WHERE data = FROM_BASE64('JyBPUiAnMSc9JzE=')",
    ])
    async def test_encoded_injection_detection(self, executor, encoded_query):
        """Test detection of encoded SQL injection attempts."""
        # Future implementation will decode and validate
        pass

    # Test Case 6: Nested Query Injection
    @pytest.mark.parametrize("nested_query", [
        "SELECT * FROM users WHERE id IN (SELECT id FROM admins)",
        "SELECT * FROM users WHERE exists(SELECT 1 FROM admins WHERE admins.id = users.id)",
        "SELECT * FROM (SELECT * FROM users UNION SELECT * FROM passwords) as combined",
    ])
    async def test_nested_query_validation(self, executor, nested_query):
        """Test validation of nested queries."""
        # For now, these should execute (future: add depth limits)
        result = await executor.execute(nested_query)
        assert result is not None

    # Test Case 7: Function-based Injection
    @pytest.mark.parametrize("function_query", [
        # Information schema access attempts
        "SELECT * FROM information_schema.tables",
        "SELECT DATABASE()",
        "SELECT USER()",
        "SELECT VERSION()",
        # File system access attempts
        "SELECT LOAD_FILE('/etc/passwd')",
        "SELECT * INTO OUTFILE '/tmp/hack.txt' FROM users",
    ])
    async def test_dangerous_function_blocking(self, executor, function_query):
        """Test blocking of dangerous MySQL functions."""
        # Future implementation will block these
        pass

    # Integration test with actual mysql_query function
    @pytest.mark.asyncio
    async def test_mysql_query_injection_prevention(self, monkeypatch):
        """Integration test for SQL injection prevention in mysql_query."""
        # Mock the connection manager
        from fastmcp_mysql.tools.query import set_connection_manager
        
        mock_manager = MagicMock(spec=ConnectionManager)
        mock_manager.execute = AsyncMock(return_value=[])
        set_connection_manager(mock_manager)
        
        # Test that parameterized queries work
        result = await mysql_query(
            "SELECT * FROM users WHERE id = %s",
            [1]
        )
        assert result["success"] is True
        
        # Test that multiple statements are blocked
        result = await mysql_query(
            "SELECT * FROM users; DROP TABLE users;"
        )
        assert result["success"] is False
        assert "Multiple statements" in result["error"]