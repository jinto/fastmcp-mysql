"""Unit tests for cache interfaces."""
import pytest
from abc import ABC
from typing import Any, Dict, List, Optional
import asyncio
from datetime import datetime, timedelta

from fastmcp_mysql.cache.interfaces import (
    CacheInterface,
    CacheEntry,
    CacheStats,
    CacheKeyGenerator,
    CacheConfig
)


class TestCacheInterface:
    """Test cache interface abstract class."""
    
    @pytest.mark.asyncio
    async def test_cache_interface_is_abstract(self):
        """Test that CacheInterface cannot be instantiated."""
        with pytest.raises(TypeError):
            CacheInterface()
    
    @pytest.mark.asyncio
    async def test_cache_interface_has_required_methods(self):
        """Test that CacheInterface has all required abstract methods."""
        assert hasattr(CacheInterface, 'get')
        assert hasattr(CacheInterface, 'set')
        assert hasattr(CacheInterface, 'delete')
        assert hasattr(CacheInterface, 'delete_pattern')
        assert hasattr(CacheInterface, 'clear')
        assert hasattr(CacheInterface, 'exists')
        assert hasattr(CacheInterface, 'get_stats')
        assert hasattr(CacheInterface, 'close')


class TestCacheEntry:
    """Test cache entry data class."""
    
    def test_cache_entry_creation(self):
        """Test creating a cache entry."""
        data = {"result": [1, 2, 3]}
        now = datetime.now()
        entry = CacheEntry(
            key="test_key",
            value=data,
            created_at=now,
            expires_at=now + timedelta(seconds=60),
            hit_count=0
        )
        
        assert entry.key == "test_key"
        assert entry.value == data
        assert entry.hit_count == 0
        assert not entry.is_expired()
    
    def test_cache_entry_expiration(self):
        """Test cache entry expiration check."""
        # Create expired entry
        entry = CacheEntry(
            key="test_key",
            value="data",
            created_at=datetime.now() - timedelta(seconds=120),
            expires_at=datetime.now() - timedelta(seconds=60),
            hit_count=5
        )
        
        assert entry.is_expired()
    
    def test_cache_entry_no_expiration(self):
        """Test cache entry without expiration."""
        entry = CacheEntry(
            key="test_key",
            value="data",
            created_at=datetime.now(),
            expires_at=None,  # No expiration
            hit_count=0
        )
        
        assert not entry.is_expired()


class TestCacheStats:
    """Test cache statistics data class."""
    
    def test_cache_stats_creation(self):
        """Test creating cache statistics."""
        stats = CacheStats(
            hits=100,
            misses=20,
            evictions=5,
            size=50,
            max_size=100
        )
        
        assert stats.hits == 100
        assert stats.misses == 20
        assert stats.evictions == 5
        assert stats.size == 50
        assert stats.max_size == 100
    
    def test_cache_stats_hit_rate(self):
        """Test cache hit rate calculation."""
        stats = CacheStats(
            hits=80,
            misses=20,
            evictions=0,
            size=10,
            max_size=100
        )
        
        assert stats.hit_rate == 0.8  # 80%
    
    def test_cache_stats_hit_rate_no_requests(self):
        """Test cache hit rate with no requests."""
        stats = CacheStats(
            hits=0,
            misses=0,
            evictions=0,
            size=0,
            max_size=100
        )
        
        assert stats.hit_rate == 0.0
    
    def test_cache_stats_utilization(self):
        """Test cache utilization calculation."""
        stats = CacheStats(
            hits=100,
            misses=20,
            evictions=5,
            size=75,
            max_size=100
        )
        
        assert stats.utilization == 0.75  # 75%


class TestCacheKeyGenerator:
    """Test cache key generator."""
    
    def test_generate_key_simple_query(self):
        """Test generating cache key for simple query."""
        generator = CacheKeyGenerator()
        
        query = "SELECT * FROM users WHERE id = %s"
        params = (123,)
        database = "test_db"
        
        key = generator.generate_key(query, params, database)
        
        assert isinstance(key, str)
        assert len(key) > 0
        assert database in key
    
    def test_generate_key_no_params(self):
        """Test generating cache key without parameters."""
        generator = CacheKeyGenerator()
        
        query = "SELECT * FROM users"
        database = "test_db"
        
        key = generator.generate_key(query, None, database)
        
        assert isinstance(key, str)
        assert len(key) > 0
    
    def test_generate_key_consistency(self):
        """Test cache key generation is consistent."""
        generator = CacheKeyGenerator()
        
        query = "SELECT * FROM users WHERE age > %s AND city = %s"
        params = (18, "New York")
        database = "test_db"
        
        key1 = generator.generate_key(query, params, database)
        key2 = generator.generate_key(query, params, database)
        
        assert key1 == key2
    
    def test_generate_key_different_queries(self):
        """Test different queries generate different keys."""
        generator = CacheKeyGenerator()
        
        query1 = "SELECT * FROM users"
        query2 = "SELECT * FROM orders"
        database = "test_db"
        
        key1 = generator.generate_key(query1, None, database)
        key2 = generator.generate_key(query2, None, database)
        
        assert key1 != key2
    
    def test_generate_key_normalized_query(self):
        """Test query normalization in key generation."""
        generator = CacheKeyGenerator()
        
        # Different whitespace, same query
        query1 = "SELECT   *   FROM   users   WHERE   id = %s"
        query2 = "SELECT * FROM users WHERE id = %s"
        params = (123,)
        database = "test_db"
        
        key1 = generator.generate_key(query1, params, database)
        key2 = generator.generate_key(query2, params, database)
        
        assert key1 == key2  # Should be same after normalization


class TestCacheConfig:
    """Test cache configuration."""
    
    def test_cache_config_defaults(self):
        """Test default cache configuration."""
        config = CacheConfig()
        
        assert config.enabled == True
        assert config.ttl == 300  # 5 minutes default
        assert config.max_size == 1000
        assert config.eviction_policy == "lru"
    
    def test_cache_config_custom(self):
        """Test custom cache configuration."""
        config = CacheConfig(
            enabled=False,
            ttl=600,
            max_size=5000,
            eviction_policy="lfu"
        )
        
        assert config.enabled == False
        assert config.ttl == 600
        assert config.max_size == 5000
        assert config.eviction_policy == "lfu"
    
    def test_cache_config_from_env(self):
        """Test cache configuration from environment variables."""
        import os
        
        # Set environment variables
        os.environ["MYSQL_CACHE_ENABLED"] = "true"
        os.environ["MYSQL_CACHE_TTL"] = "1800"
        os.environ["MYSQL_CACHE_MAX_SIZE"] = "2000"
        
        config = CacheConfig.from_env()
        
        assert config.enabled == True
        assert config.ttl == 1800
        assert config.max_size == 2000
        
        # Cleanup
        del os.environ["MYSQL_CACHE_ENABLED"]
        del os.environ["MYSQL_CACHE_TTL"]
        del os.environ["MYSQL_CACHE_MAX_SIZE"]


# Mock implementation for testing
class MockCache(CacheInterface):
    """Mock cache implementation for testing."""
    
    def __init__(self):
        self._storage: Dict[str, CacheEntry] = {}
        self._stats = CacheStats(0, 0, 0, 0, 1000)
    
    async def get(self, key: str) -> Optional[Any]:
        entry = self._storage.get(key)
        if entry and not entry.is_expired():
            self._stats.hits += 1
            entry.hit_count += 1
            return entry.value
        self._stats.misses += 1
        return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        expires_at = None
        if ttl:
            expires_at = datetime.now() + timedelta(seconds=ttl)
        
        self._storage[key] = CacheEntry(
            key=key,
            value=value,
            created_at=datetime.now(),
            expires_at=expires_at,
            hit_count=0
        )
        self._stats.size = len(self._storage)
    
    async def delete(self, key: str) -> bool:
        if key in self._storage:
            del self._storage[key]
            self._stats.size = len(self._storage)
            return True
        return False
    
    async def delete_pattern(self, pattern: str) -> int:
        # Simple pattern matching (just prefix for mock)
        prefix = pattern.rstrip('*')
        keys_to_delete = [k for k in self._storage if k.startswith(prefix)]
        
        for key in keys_to_delete:
            del self._storage[key]
        
        self._stats.size = len(self._storage)
        return len(keys_to_delete)
    
    async def clear(self) -> None:
        self._storage.clear()
        self._stats.size = 0
        self._stats.evictions += len(self._storage)
    
    async def exists(self, key: str) -> bool:
        entry = self._storage.get(key)
        return entry is not None and not entry.is_expired()
    
    async def get_stats(self) -> CacheStats:
        return self._stats
    
    async def close(self) -> None:
        await self.clear()


class TestMockCache:
    """Test mock cache implementation."""
    
    @pytest.mark.asyncio
    async def test_mock_cache_basic_operations(self):
        """Test basic cache operations."""
        cache = MockCache()
        
        # Test set and get
        await cache.set("key1", "value1")
        assert await cache.get("key1") == "value1"
        
        # Test miss
        assert await cache.get("nonexistent") is None
        
        # Test delete
        assert await cache.delete("key1") == True
        assert await cache.get("key1") is None
        
        # Test stats
        stats = await cache.get_stats()
        assert stats.hits == 1
        assert stats.misses == 2
    
    @pytest.mark.asyncio
    async def test_mock_cache_ttl(self):
        """Test cache TTL functionality."""
        cache = MockCache()
        
        # Set with very short TTL (negative to ensure expiration)
        await cache.set("key1", "value1", ttl=-1)
        
        # Should be expired immediately
        assert await cache.get("key1") is None
        
        # Test with positive TTL
        await cache.set("key2", "value2", ttl=10)
        assert await cache.get("key2") == "value2"
    
    @pytest.mark.asyncio
    async def test_mock_cache_pattern_delete(self):
        """Test pattern-based deletion."""
        cache = MockCache()
        
        # Set multiple keys
        await cache.set("user:1", "data1")
        await cache.set("user:2", "data2")
        await cache.set("order:1", "data3")
        
        # Delete by pattern
        deleted = await cache.delete_pattern("user:*")
        assert deleted == 2
        
        # Check remaining
        assert await cache.get("user:1") is None
        assert await cache.get("user:2") is None
        assert await cache.get("order:1") == "data3"