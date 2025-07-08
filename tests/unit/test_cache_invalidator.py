"""Unit tests for cache invalidation logic."""
import pytest
from typing import Dict, Set
from unittest.mock import Mock, AsyncMock

from fastmcp_mysql.cache.invalidator import (
    CacheInvalidator,
    InvalidationStrategy,
    QueryType,
    TableDependency
)
from fastmcp_mysql.cache.interfaces import CacheInterface


class MockCache(CacheInterface):
    """Mock cache for testing."""
    
    def __init__(self):
        self.deleted_patterns: Set[str] = set()
        self.cleared = False
    
    async def get(self, key: str):
        return None
    
    async def set(self, key: str, value, ttl=None):
        pass
    
    async def delete(self, key: str):
        return True
    
    async def delete_pattern(self, pattern: str):
        self.deleted_patterns.add(pattern)
        return 1
    
    async def clear(self):
        self.cleared = True
    
    async def exists(self, key: str):
        return False
    
    async def get_stats(self):
        return None
    
    async def close(self):
        pass


class TestCacheInvalidator:
    """Test cache invalidation logic."""
    
    @pytest.mark.asyncio
    async def test_invalidator_creation(self):
        """Test creating a cache invalidator."""
        invalidator = CacheInvalidator()
        
        assert invalidator is not None
        assert isinstance(invalidator.strategy, InvalidationStrategy)
    
    @pytest.mark.asyncio
    async def test_query_type_detection(self):
        """Test detecting query types."""
        invalidator = CacheInvalidator()
        
        # SELECT queries
        assert invalidator.get_query_type("SELECT * FROM users") == QueryType.SELECT
        assert invalidator.get_query_type("select id from orders") == QueryType.SELECT
        
        # INSERT queries
        assert invalidator.get_query_type("INSERT INTO users VALUES (1, 'test')") == QueryType.INSERT
        assert invalidator.get_query_type("insert into logs (msg) values ('test')") == QueryType.INSERT
        
        # UPDATE queries
        assert invalidator.get_query_type("UPDATE users SET name='test'") == QueryType.UPDATE
        assert invalidator.get_query_type("update orders set status=1") == QueryType.UPDATE
        
        # DELETE queries
        assert invalidator.get_query_type("DELETE FROM users WHERE id=1") == QueryType.DELETE
        assert invalidator.get_query_type("delete from logs") == QueryType.DELETE
        
        # DDL queries
        assert invalidator.get_query_type("CREATE TABLE test (id INT)") == QueryType.DDL
        assert invalidator.get_query_type("ALTER TABLE users ADD COLUMN age INT") == QueryType.DDL
        assert invalidator.get_query_type("DROP TABLE temp") == QueryType.DDL
        assert invalidator.get_query_type("TRUNCATE TABLE logs") == QueryType.DDL
    
    @pytest.mark.asyncio
    async def test_table_extraction(self):
        """Test extracting tables from queries."""
        invalidator = CacheInvalidator()
        
        # Simple queries
        tables = invalidator.extract_tables("SELECT * FROM users")
        assert tables == ["users"]
        
        tables = invalidator.extract_tables("INSERT INTO orders (id) VALUES (1)")
        assert tables == ["orders"]
        
        tables = invalidator.extract_tables("UPDATE products SET price = 100")
        assert tables == ["products"]
        
        tables = invalidator.extract_tables("DELETE FROM logs WHERE old = 1")
        assert tables == ["logs"]
        
        # JOIN queries
        tables = invalidator.extract_tables(
            "SELECT * FROM users u JOIN orders o ON u.id = o.user_id"
        )
        assert set(tables) == {"users", "orders"}
        
        # Multiple JOINs
        tables = invalidator.extract_tables(
            "SELECT * FROM users u "
            "JOIN orders o ON u.id = o.user_id "
            "JOIN products p ON o.product_id = p.id"
        )
        assert set(tables) == {"users", "orders", "products"}
        
        # Subqueries
        tables = invalidator.extract_tables(
            "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders)"
        )
        assert set(tables) == {"users", "orders"}
    
    @pytest.mark.asyncio
    async def test_basic_invalidation(self):
        """Test basic cache invalidation for write operations."""
        cache = MockCache()
        invalidator = CacheInvalidator()
        
        # INSERT invalidation
        await invalidator.invalidate_on_write(
            "INSERT INTO users VALUES (1, 'test')",
            cache
        )
        assert "*:users:*" in cache.deleted_patterns
        
        # UPDATE invalidation
        cache.deleted_patterns.clear()
        await invalidator.invalidate_on_write(
            "UPDATE orders SET status = 'complete'",
            cache
        )
        assert "*:orders:*" in cache.deleted_patterns
        
        # DELETE invalidation
        cache.deleted_patterns.clear()
        await invalidator.invalidate_on_write(
            "DELETE FROM products WHERE expired = 1",
            cache
        )
        assert "*:products:*" in cache.deleted_patterns
    
    @pytest.mark.asyncio
    async def test_join_invalidation(self):
        """Test invalidation for queries with JOINs."""
        cache = MockCache()
        invalidator = CacheInvalidator()
        
        # UPDATE with JOIN should invalidate all involved tables
        await invalidator.invalidate_on_write(
            "UPDATE users u JOIN orders o ON u.id = o.user_id SET u.total = o.amount",
            cache
        )
        
        assert "*:users:*" in cache.deleted_patterns
        assert "*:orders:*" in cache.deleted_patterns
    
    @pytest.mark.asyncio
    async def test_ddl_invalidation(self):
        """Test invalidation for DDL operations."""
        cache = MockCache()
        invalidator = CacheInvalidator()
        
        # DDL should clear entire cache
        await invalidator.invalidate_on_write(
            "ALTER TABLE users ADD COLUMN age INT",
            cache
        )
        
        assert cache.cleared
    
    @pytest.mark.asyncio
    async def test_select_no_invalidation(self):
        """Test that SELECT queries don't trigger invalidation."""
        cache = MockCache()
        invalidator = CacheInvalidator()
        
        await invalidator.invalidate_on_write(
            "SELECT * FROM users",
            cache
        )
        
        assert len(cache.deleted_patterns) == 0
        assert not cache.cleared
    
    @pytest.mark.asyncio
    async def test_custom_invalidation_strategy(self):
        """Test custom invalidation strategies."""
        # Conservative strategy - only invalidate exact table
        cache = MockCache()
        invalidator = CacheInvalidator(strategy=InvalidationStrategy.CONSERVATIVE)
        
        await invalidator.invalidate_on_write(
            "INSERT INTO users VALUES (1, 'test')",
            cache
        )
        
        # Should invalidate with more specific pattern
        assert any("users" in pattern for pattern in cache.deleted_patterns)
        
        # Aggressive strategy - invalidate related tables too
        cache = MockCache()
        invalidator = CacheInvalidator(strategy=InvalidationStrategy.AGGRESSIVE)
        
        # Add table dependencies
        invalidator.add_dependency("orders", ["users", "products"])
        
        await invalidator.invalidate_on_write(
            "UPDATE orders SET status = 1",
            cache
        )
        
        # Should invalidate orders and its dependencies
        assert "*:orders:*" in cache.deleted_patterns
        assert "*:users:*" in cache.deleted_patterns
        assert "*:products:*" in cache.deleted_patterns
    
    @pytest.mark.asyncio
    async def test_table_dependencies(self):
        """Test managing table dependencies."""
        invalidator = CacheInvalidator()
        
        # Add dependencies
        invalidator.add_dependency("orders", ["users", "products"])
        invalidator.add_dependency("order_items", ["orders", "products"])
        
        # Get dependencies
        deps = invalidator.get_dependencies("orders")
        assert set(deps) == {"users", "products"}
        
        # Transitive dependencies
        all_deps = invalidator.get_all_dependencies("order_items")
        assert "orders" in all_deps
        assert "products" in all_deps
        assert "users" in all_deps  # Through orders
        
        # Remove dependency
        invalidator.remove_dependency("orders", "products")
        deps = invalidator.get_dependencies("orders")
        assert deps == ["users"]
    
    @pytest.mark.asyncio
    async def test_pattern_generation(self):
        """Test cache key pattern generation."""
        invalidator = CacheInvalidator()
        
        # Basic patterns
        pattern = invalidator.generate_pattern("users")
        assert pattern == "*:users:*"
        
        pattern = invalidator.generate_pattern("orders", prefix="db1")
        assert pattern == "db1:*:orders:*"
        
        # Multiple tables
        patterns = invalidator.generate_patterns(["users", "orders"])
        assert "*:users:*" in patterns
        assert "*:orders:*" in patterns
    
    @pytest.mark.asyncio
    async def test_conditional_invalidation(self):
        """Test conditional invalidation based on query analysis."""
        cache = MockCache()
        invalidator = CacheInvalidator()
        
        # Specific WHERE clause - could use targeted invalidation
        await invalidator.invalidate_on_write(
            "UPDATE users SET name = 'test' WHERE id = 123",
            cache,
            targeted=True
        )
        
        # With targeted mode, could invalidate more specifically
        # (implementation would analyze WHERE clause)
        assert len(cache.deleted_patterns) > 0
    
    @pytest.mark.asyncio
    async def test_batch_invalidation(self):
        """Test batch invalidation for multiple operations."""
        cache = MockCache()
        invalidator = CacheInvalidator()
        
        queries = [
            "INSERT INTO users VALUES (1, 'test')",
            "UPDATE orders SET status = 1",
            "DELETE FROM logs WHERE old = 1"
        ]
        
        await invalidator.invalidate_batch(queries, cache)
        
        assert "*:users:*" in cache.deleted_patterns
        assert "*:orders:*" in cache.deleted_patterns
        assert "*:logs:*" in cache.deleted_patterns
    
    @pytest.mark.asyncio
    async def test_invalidation_with_database_context(self):
        """Test invalidation with database context."""
        cache = MockCache()
        invalidator = CacheInvalidator()
        
        # Invalidate with database context
        await invalidator.invalidate_on_write(
            "INSERT INTO users VALUES (1, 'test')",
            cache,
            database="mydb"
        )
        
        # Should include database in pattern
        assert any("mydb" in pattern for pattern in cache.deleted_patterns)