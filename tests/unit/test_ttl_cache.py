"""Unit tests for TTL-based cache implementation."""
import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import patch

from fastmcp_mysql.cache.ttl_cache import TTLCache
from fastmcp_mysql.cache.interfaces import CacheConfig, CacheStats


class TestTTLCache:
    """Test TTL-based cache implementation."""
    
    @pytest.mark.asyncio
    async def test_ttl_cache_creation(self):
        """Test creating a TTL cache."""
        config = CacheConfig(max_size=100, ttl=300)
        cache = TTLCache(config)
        
        assert cache.config == config
        assert cache.max_size == 100
        assert cache.default_ttl == 300
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_basic_set_get(self):
        """Test basic set and get operations."""
        cache = TTLCache(CacheConfig(max_size=10))
        
        # Set and get
        await cache.set("key1", "value1")
        assert await cache.get("key1") == "value1"
        
        # Non-existent key
        assert await cache.get("nonexistent") is None
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_ttl_expiration(self):
        """Test TTL expiration."""
        cache = TTLCache(CacheConfig(max_size=10, ttl=1))
        
        # Set with default TTL
        await cache.set("key1", "value1")
        assert await cache.get("key1") == "value1"
        
        # Wait for expiration
        await asyncio.sleep(1.1)
        assert await cache.get("key1") is None
        
        # Set with custom TTL
        await cache.set("key2", "value2", ttl=2)
        assert await cache.get("key2") == "value2"
        
        await asyncio.sleep(1)
        assert await cache.get("key2") == "value2"  # Still valid
        
        await asyncio.sleep(1.1)
        assert await cache.get("key2") is None  # Now expired
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_no_ttl(self):
        """Test entries without TTL."""
        cache = TTLCache(CacheConfig(max_size=10))
        
        # Set without TTL (should use default)
        await cache.set("key1", "value1")
        assert await cache.get("key1") == "value1"
        
        # Set with None TTL (no expiration)
        await cache.set("key2", "value2", ttl=None)
        await asyncio.sleep(0.1)
        assert await cache.get("key2") == "value2"
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_delete_operations(self):
        """Test delete operations."""
        cache = TTLCache(CacheConfig(max_size=10))
        
        # Set some values
        await cache.set("key1", "value1")
        await cache.set("key2", "value2")
        
        # Delete existing key
        assert await cache.delete("key1") is True
        assert await cache.get("key1") is None
        
        # Delete non-existent key
        assert await cache.delete("nonexistent") is False
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_exists_check(self):
        """Test exists functionality."""
        cache = TTLCache(CacheConfig(max_size=10))
        
        await cache.set("key1", "value1")
        
        assert await cache.exists("key1") is True
        assert await cache.exists("nonexistent") is False
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_clear_cache(self):
        """Test clearing the cache."""
        cache = TTLCache(CacheConfig(max_size=10))
        
        # Add multiple entries
        for i in range(5):
            await cache.set(f"key{i}", f"value{i}")
        
        stats = await cache.get_stats()
        assert stats.size == 5
        
        # Clear cache
        await cache.clear()
        
        stats = await cache.get_stats()
        assert stats.size == 0
        
        # Verify all entries are gone
        for i in range(5):
            assert await cache.get(f"key{i}") is None
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_max_size_eviction(self):
        """Test eviction when max size is reached."""
        cache = TTLCache(CacheConfig(max_size=3))
        
        # Fill cache
        await cache.set("key1", "value1")
        await cache.set("key2", "value2")
        await cache.set("key3", "value3")
        
        stats = await cache.get_stats()
        assert stats.size == 3
        
        # Add one more - should evict oldest
        await cache.set("key4", "value4")
        
        stats = await cache.get_stats()
        assert stats.size == 3
        assert stats.evictions == 1
        
        # key1 should be evicted (FIFO)
        assert await cache.get("key1") is None
        assert await cache.get("key4") == "value4"
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_cache_stats(self):
        """Test cache statistics."""
        cache = TTLCache(CacheConfig(max_size=10))
        
        # Initial stats
        stats = await cache.get_stats()
        assert stats.hits == 0
        assert stats.misses == 0
        assert stats.size == 0
        assert stats.evictions == 0
        
        # Add entries
        await cache.set("key1", "value1")
        await cache.set("key2", "value2")
        
        # Get hits and misses
        assert await cache.get("key1") == "value1"  # Hit
        assert await cache.get("key1") == "value1"  # Hit
        assert await cache.get("key3") is None      # Miss
        
        stats = await cache.get_stats()
        assert stats.hits == 2
        assert stats.misses == 1
        assert stats.size == 2
        assert stats.hit_rate == 2/3
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_delete_pattern(self):
        """Test pattern-based deletion."""
        cache = TTLCache(CacheConfig(max_size=10))
        
        # Add entries with patterns
        await cache.set("user:1", "data1")
        await cache.set("user:2", "data2")
        await cache.set("user:3", "data3")
        await cache.set("order:1", "order1")
        await cache.set("order:2", "order2")
        
        # Delete by pattern
        deleted = await cache.delete_pattern("user:*")
        assert deleted == 3
        
        # Verify deletions
        assert await cache.get("user:1") is None
        assert await cache.get("user:2") is None
        assert await cache.get("user:3") is None
        assert await cache.get("order:1") == "order1"
        assert await cache.get("order:2") == "order2"
        
        # Test glob patterns
        await cache.set("test_1", "value1")
        await cache.set("test_2", "value2")
        await cache.set("prod_1", "value3")
        
        deleted = await cache.delete_pattern("test_*")
        assert deleted == 2
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        """Test concurrent access to cache."""
        cache = TTLCache(CacheConfig(max_size=100))
        
        async def writer(key_prefix: str, count: int):
            for i in range(count):
                await cache.set(f"{key_prefix}:{i}", f"value_{i}")
        
        async def reader(key_prefix: str, count: int):
            hits = 0
            for i in range(count):
                if await cache.get(f"{key_prefix}:{i}") is not None:
                    hits += 1
            return hits
        
        # Run concurrent operations
        writers = [writer(f"prefix{i}", 10) for i in range(5)]
        readers = [reader(f"prefix{i}", 10) for i in range(5)]
        
        await asyncio.gather(*writers)
        hits = await asyncio.gather(*readers)
        
        # All reads should hit
        assert all(h == 10 for h in hits)
        
        stats = await cache.get_stats()
        assert stats.size == 50  # 5 prefixes * 10 entries
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_entries(self):
        """Test automatic cleanup of expired entries."""
        cache = TTLCache(CacheConfig(max_size=10, cleanup_interval=0.1))
        
        # Add entries with short TTL
        await cache.set("key1", "value1", ttl=0.2)
        await cache.set("key2", "value2", ttl=0.2)
        await cache.set("key3", "value3", ttl=10)  # Long TTL
        
        # Wait for expiration and cleanup
        await asyncio.sleep(0.5)
        
        # Force cleanup by accessing cache
        await cache.get("key1")
        
        stats = await cache.get_stats()
        # Only key3 should remain
        assert stats.size == 1
        assert await cache.get("key3") == "value3"
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_get_many_set_many(self):
        """Test batch get and set operations."""
        cache = TTLCache(CacheConfig(max_size=10))
        
        # Set many
        items = {f"key{i}": f"value{i}" for i in range(5)}
        await cache.set_many(items)
        
        # Get many
        keys = list(items.keys())
        result = await cache.get_many(keys)
        
        assert result == items
        
        # Get many with some missing
        keys.append("nonexistent")
        result = await cache.get_many(keys)
        
        assert len(result) == 5
        assert "nonexistent" not in result
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_increment_operation(self):
        """Test increment operation."""
        cache = TTLCache(CacheConfig(max_size=10))
        
        # Increment non-existent key
        result = await cache.increment("counter")
        assert result == 1
        
        # Increment existing key
        result = await cache.increment("counter", delta=5)
        assert result == 6
        
        # Try to increment non-numeric value
        await cache.set("string_key", "not_a_number")
        with pytest.raises(ValueError):
            await cache.increment("string_key")
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_memory_efficiency(self):
        """Test memory efficiency with expired entries."""
        cache = TTLCache(CacheConfig(max_size=1000))
        
        # Add many entries with short TTL
        for i in range(100):
            await cache.set(f"key{i}", f"value{i}", ttl=0.1)
        
        # Wait for expiration
        await asyncio.sleep(0.2)
        
        # Add new entries - should trigger cleanup
        for i in range(100, 200):
            await cache.set(f"key{i}", f"value{i}")
        
        stats = await cache.get_stats()
        # Should have cleaned up expired entries
        assert stats.size == 100
        
        await cache.close()