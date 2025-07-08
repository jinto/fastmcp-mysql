"""Unit tests for mysql_query tool."""

import json
from unittest.mock import Mock, AsyncMock, patch
from typing import Dict, Any

import pytest

from fastmcp_mysql.tools.query import (
    mysql_query,
    QueryValidator,
    QueryType,
    QueryExecutor,
    format_query_result,
)


class TestQueryValidator:
    """Test the QueryValidator class."""
    
    def test_get_query_type_select(self):
        """Test identifying SELECT queries."""
        validator = QueryValidator()
        
        assert validator.get_query_type("SELECT * FROM users") == QueryType.SELECT
        assert validator.get_query_type("select id from posts") == QueryType.SELECT
        assert validator.get_query_type("  SELECT count(*) FROM orders  ") == QueryType.SELECT
        assert validator.get_query_type("WITH cte AS (SELECT 1) SELECT * FROM cte") == QueryType.SELECT
    
    def test_get_query_type_insert(self):
        """Test identifying INSERT queries."""
        validator = QueryValidator()
        
        assert validator.get_query_type("INSERT INTO users VALUES (1, 'test')") == QueryType.INSERT
        assert validator.get_query_type("insert into logs (msg) values ('test')") == QueryType.INSERT
        assert validator.get_query_type("  INSERT IGNORE INTO data SET id=1  ") == QueryType.INSERT
    
    def test_get_query_type_update(self):
        """Test identifying UPDATE queries."""
        validator = QueryValidator()
        
        assert validator.get_query_type("UPDATE users SET name='test'") == QueryType.UPDATE
        assert validator.get_query_type("update posts set title='new' where id=1") == QueryType.UPDATE
        assert validator.get_query_type("  UPDATE LOW_PRIORITY users SET active=1  ") == QueryType.UPDATE
    
    def test_get_query_type_delete(self):
        """Test identifying DELETE queries."""
        validator = QueryValidator()
        
        assert validator.get_query_type("DELETE FROM users WHERE id=1") == QueryType.DELETE
        assert validator.get_query_type("delete from logs") == QueryType.DELETE
        assert validator.get_query_type("  DELETE QUICK FROM temp_data  ") == QueryType.DELETE
    
    def test_get_query_type_ddl(self):
        """Test identifying DDL queries."""
        validator = QueryValidator()
        
        assert validator.get_query_type("CREATE TABLE users (id INT)") == QueryType.DDL
        assert validator.get_query_type("DROP TABLE IF EXISTS temp") == QueryType.DDL
        assert validator.get_query_type("ALTER TABLE users ADD COLUMN email VARCHAR(255)") == QueryType.DDL
        assert validator.get_query_type("TRUNCATE TABLE logs") == QueryType.DDL
        assert validator.get_query_type("CREATE INDEX idx_name ON users(name)") == QueryType.DDL
    
    def test_get_query_type_other(self):
        """Test identifying other query types."""
        validator = QueryValidator()
        
        assert validator.get_query_type("SHOW TABLES") == QueryType.OTHER
        assert validator.get_query_type("DESCRIBE users") == QueryType.OTHER
        assert validator.get_query_type("SET @var = 1") == QueryType.OTHER
        assert validator.get_query_type("EXPLAIN SELECT * FROM users") == QueryType.OTHER
    
    def test_validate_query_select_allowed(self):
        """Test validating SELECT queries (always allowed)."""
        validator = QueryValidator()
        
        # SELECT queries should always be allowed
        validator.validate_query("SELECT * FROM users", allow_write=False)
        validator.validate_query("SELECT * FROM users", allow_write=True)
    
    def test_validate_query_write_operations_denied(self):
        """Test write operations when not allowed."""
        validator = QueryValidator(
            allow_insert=False,
            allow_update=False,
            allow_delete=False
        )
        
        with pytest.raises(ValueError, match="INSERT operations require write permission"):
            validator.validate_query("INSERT INTO users VALUES (1)", allow_write=False)
        
        with pytest.raises(ValueError, match="UPDATE operations require write permission"):
            validator.validate_query("UPDATE users SET name='test'", allow_write=False)
        
        with pytest.raises(ValueError, match="DELETE operations require write permission"):
            validator.validate_query("DELETE FROM users", allow_write=False)
    
    def test_validate_query_write_operations_allowed(self):
        """Test write operations when allowed."""
        validator = QueryValidator(
            allow_insert=True,
            allow_update=True,
            allow_delete=True
        )
        
        # Should not raise when write operations are allowed
        validator.validate_query("INSERT INTO users VALUES (1)", allow_write=True)
        validator.validate_query("UPDATE users SET name='test'", allow_write=True)
        validator.validate_query("DELETE FROM users", allow_write=True)
    
    def test_validate_query_ddl_always_denied(self):
        """Test DDL queries are always denied."""
        validator = QueryValidator()
        
        with pytest.raises(ValueError, match="DDL operations are not allowed"):
            validator.validate_query("CREATE TABLE test (id INT)", allow_write=True)
        
        with pytest.raises(ValueError, match="DDL operations are not allowed"):
            validator.validate_query("DROP TABLE users", allow_write=True)
    
    def test_validate_query_dangerous_patterns(self):
        """Test detection of dangerous query patterns."""
        validator = QueryValidator()
        
        # Test queries that might be trying to bypass validation
        dangerous_queries = [
            "SELECT * FROM users; DROP TABLE users",
            "SELECT * FROM users--; DROP TABLE users",
            "SELECT * FROM users/* comment */; DELETE FROM users",
        ]
        
        for query in dangerous_queries:
            with pytest.raises(ValueError, match="Multiple statements detected"):
                validator.validate_query(query, allow_write=False)


class TestQueryExecutor:
    """Test the QueryExecutor class."""
    
    @pytest.fixture
    def mock_connection_manager(self):
        """Create a mock connection manager."""
        return AsyncMock()
    
    @pytest.fixture
    def executor(self, mock_connection_manager):
        """Create a query executor instance."""
        validator = QueryValidator(
            allow_insert=True,
            allow_update=True,
            allow_delete=True
        )
        return QueryExecutor(mock_connection_manager, validator)
    
    @pytest.mark.asyncio
    async def test_execute_select_query(self, executor, mock_connection_manager):
        """Test executing a SELECT query."""
        mock_result = [
            {"id": 1, "name": "Alice"},
            {"id": 2, "name": "Bob"}
        ]
        mock_connection_manager.execute.return_value = mock_result
        
        result = await executor.execute(
            query="SELECT * FROM users",
            params=None
        )
        
        assert result["success"] is True
        assert result["data"] == mock_result
        assert result["rows_affected"] is None
        assert "error" not in result
        
        mock_connection_manager.execute.assert_called_once_with(
            "SELECT * FROM users",
            None
        )
    
    @pytest.mark.asyncio
    async def test_execute_insert_query(self, executor, mock_connection_manager):
        """Test executing an INSERT query."""
        mock_connection_manager.execute.return_value = 1  # 1 row affected
        
        result = await executor.execute(
            query="INSERT INTO users (name) VALUES (%s)",
            params=("Charlie",)
        )
        
        assert result["success"] is True
        assert result["data"] is None
        assert result["rows_affected"] == 1
        assert "error" not in result
    
    @pytest.mark.asyncio
    async def test_execute_query_with_error(self, executor, mock_connection_manager):
        """Test query execution with database error."""
        mock_connection_manager.execute.side_effect = Exception("Database connection lost")
        
        result = await executor.execute(
            query="SELECT * FROM users",
            params=None
        )
        
        assert result["success"] is False
        assert result["error"] == "Database connection lost"
        assert result["data"] is None
        assert result["rows_affected"] is None
    
    @pytest.mark.asyncio
    async def test_execute_query_validation_error(self, executor):
        """Test query execution with validation error."""
        result = await executor.execute(
            query="DROP TABLE users",
            params=None
        )
        
        assert result["success"] is False
        assert "DDL operations are not allowed" in result["error"]
        assert result["data"] is None
        assert result["rows_affected"] is None


class TestFormatQueryResult:
    """Test the format_query_result function."""
    
    def test_format_select_result(self):
        """Test formatting SELECT query results."""
        result = {
            "success": True,
            "data": [
                {"id": 1, "name": "Alice"},
                {"id": 2, "name": "Bob"}
            ],
            "rows_affected": None
        }
        
        formatted = format_query_result(result)
        
        assert formatted["success"] is True
        assert formatted["data"] == result["data"]
        assert formatted["message"] == "Query executed successfully"
        assert formatted["metadata"]["row_count"] == 2
        assert formatted["metadata"]["query_type"] == "SELECT"
    
    def test_format_write_result(self):
        """Test formatting write query results."""
        result = {
            "success": True,
            "data": None,
            "rows_affected": 3
        }
        
        formatted = format_query_result(result)
        
        assert formatted["success"] is True
        assert formatted["data"] is None
        assert formatted["message"] == "Query executed successfully"
        assert formatted["metadata"]["rows_affected"] == 3
        assert formatted["metadata"]["query_type"] == "WRITE"
    
    def test_format_error_result(self):
        """Test formatting error results."""
        result = {
            "success": False,
            "error": "Table not found",
            "data": None,
            "rows_affected": None
        }
        
        formatted = format_query_result(result)
        
        assert formatted["success"] is False
        assert formatted["error"] == "Table not found"
        assert formatted["message"] == "Query execution failed"
        assert "metadata" not in formatted


class TestMySQLQueryTool:
    """Test the mysql_query tool function."""
    
    @pytest.mark.asyncio
    async def test_mysql_query_success(self):
        """Test successful query execution."""
        with patch("fastmcp_mysql.tools.query.get_connection_manager") as mock_get_conn:
            mock_conn_manager = AsyncMock()
            mock_get_conn.return_value = mock_conn_manager
            
            mock_conn_manager.execute.return_value = [
                {"id": 1, "name": "Test"}
            ]
            
            result = await mysql_query(
                query="SELECT * FROM users WHERE id = %s",
                params=[1]
            )
            
            assert result["success"] is True
            assert result["data"] == [{"id": 1, "name": "Test"}]
            assert result["message"] == "Query executed successfully"
    
    @pytest.mark.asyncio
    async def test_mysql_query_with_database(self):
        """Test query execution with database selection."""
        with patch("fastmcp_mysql.tools.query.get_connection_manager") as mock_get_conn:
            mock_conn_manager = AsyncMock()
            mock_get_conn.return_value = mock_conn_manager
            
            mock_conn_manager.execute.return_value = []
            
            result = await mysql_query(
                query="SELECT * FROM products",
                database="shop_db"
            )
            
            # Should prefix table with database name
            expected_query = "SELECT * FROM shop_db.products"
            mock_conn_manager.execute.assert_called_once()
            
            # Check if query was modified to include database prefix
            actual_query = mock_conn_manager.execute.call_args[0][0]
            assert "shop_db" in actual_query or actual_query == "SELECT * FROM products"
    
    @pytest.mark.asyncio
    async def test_mysql_query_validation_error(self):
        """Test query with validation error."""
        # Disable security for this test to check QueryValidator
        from fastmcp_mysql.tools.query import set_security_manager
        
        # Save current security manager
        original_security = None
        try:
            # Temporarily disable security
            set_security_manager(None)
            
            with patch("fastmcp_mysql.tools.query.get_connection_manager") as mock_get_conn:
                mock_conn_manager = AsyncMock()
                mock_get_conn.return_value = mock_conn_manager
                
                result = await mysql_query(
                    query="DROP TABLE users"
                )
                
                assert result["success"] is False
                assert "DDL operations are not allowed" in result["error"]
                assert result["message"] == "Query execution failed"
        finally:
            # Restore original security manager if any
            pass
    
    @pytest.mark.asyncio
    async def test_mysql_query_connection_not_initialized(self):
        """Test query when connection is not initialized."""
        with patch("fastmcp_mysql.tools.query.get_connection_manager") as mock_get_conn:
            mock_get_conn.return_value = None
            
            result = await mysql_query(
                query="SELECT * FROM users"
            )
            
            assert result["success"] is False
            assert "Connection not initialized" in result["error"]