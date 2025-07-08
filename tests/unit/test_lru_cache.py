"""Unit tests for LRU cache implementation."""
import pytest
import asyncio
from datetime import datetime, timedelta

from fastmcp_mysql.cache.lru_cache import LRUCache
from fastmcp_mysql.cache.interfaces import CacheConfig, CacheStats


class TestLRUCache:
    """Test LRU (Least Recently Used) cache implementation."""
    
    @pytest.mark.asyncio
    async def test_lru_cache_creation(self):
        """Test creating an LRU cache."""
        config = CacheConfig(max_size=100, ttl=300, eviction_policy="lru")
        cache = LRUCache(config)
        
        assert cache.config == config
        assert cache.max_size == 100
        assert cache.default_ttl == 300
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_basic_operations(self):
        """Test basic cache operations."""
        cache = LRUCache(CacheConfig(max_size=10))
        
        # Set and get
        await cache.set("key1", "value1")
        assert await cache.get("key1") == "value1"
        
        # Update existing key
        await cache.set("key1", "new_value1")
        assert await cache.get("key1") == "new_value1"
        
        # Non-existent key
        assert await cache.get("nonexistent") is None
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_lru_eviction(self):
        """Test LRU eviction policy."""
        cache = LRUCache(CacheConfig(max_size=3))
        
        # Fill cache
        await cache.set("key1", "value1")
        await cache.set("key2", "value2")
        await cache.set("key3", "value3")
        
        # Access key1 and key3 to make them recently used
        await cache.get("key1")
        await cache.get("key3")
        
        # Add new key - should evict key2 (least recently used)
        await cache.set("key4", "value4")
        
        # Check eviction
        assert await cache.get("key1") == "value1"  # Still exists
        assert await cache.get("key2") is None      # Evicted
        assert await cache.get("key3") == "value3"  # Still exists
        assert await cache.get("key4") == "value4"  # New key
        
        stats = await cache.get_stats()
        assert stats.evictions == 1
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_lru_order_maintenance(self):
        """Test that LRU order is properly maintained."""
        cache = LRUCache(CacheConfig(max_size=4))
        
        # Add items in order
        await cache.set("a", "1")
        await cache.set("b", "2")
        await cache.set("c", "3")
        await cache.set("d", "4")
        
        # At this point, order is: a, b, c, d (a is LRU)
        
        # Access in different order: b, d, a, c
        await cache.get("b")  # Order: a, c, d, b
        await cache.get("d")  # Order: a, c, b, d
        await cache.get("a")  # Order: c, b, d, a
        await cache.get("c")  # Order: b, d, a, c
        
        # Add new item - should evict 'b' (least recently used)
        await cache.set("e", "5")
        
        # Check LRU order for debugging
        lru_order = await cache.get_lru_order()
        print(f"LRU order after adding 'e': {lru_order}")
        
        # 'b' should be evicted as it was least recently accessed
        assert await cache.get("b") is None
        assert await cache.get("d") == "4"
        assert await cache.get("a") == "1"
        assert await cache.get("c") == "3"
        assert await cache.get("e") == "5"
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_update_moves_to_front(self):
        """Test that updating a key moves it to most recently used."""
        cache = LRUCache(CacheConfig(max_size=3))
        
        # Fill cache
        await cache.set("key1", "value1")
        await cache.set("key2", "value2")
        await cache.set("key3", "value3")
        
        # Update key1 - should move to front
        await cache.set("key1", "updated_value1")
        
        # Add new key - should evict key2 (now least recently used)
        await cache.set("key4", "value4")
        
        assert await cache.get("key1") == "updated_value1"  # Still exists (was updated)
        assert await cache.get("key2") is None              # Evicted
        assert await cache.get("key3") == "value3"          # Still exists
        assert await cache.get("key4") == "value4"          # New key
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_ttl_with_lru(self):
        """Test TTL expiration with LRU eviction."""
        cache = LRUCache(CacheConfig(max_size=10, ttl=1))
        
        # Add items with default TTL
        await cache.set("key1", "value1")
        await cache.set("key2", "value2")
        
        # Add item with custom TTL
        await cache.set("key3", "value3", ttl=5)
        
        # Wait for first two to expire
        await asyncio.sleep(1.1)
        
        # Expired items should return None
        assert await cache.get("key1") is None
        assert await cache.get("key2") is None
        assert await cache.get("key3") == "value3"  # Still valid
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_delete_operations(self):
        """Test delete operations."""
        cache = LRUCache(CacheConfig(max_size=10))
        
        # Add items
        await cache.set("key1", "value1")
        await cache.set("key2", "value2")
        await cache.set("key3", "value3")
        
        # Delete existing key
        assert await cache.delete("key2") is True
        assert await cache.get("key2") is None
        
        # Delete non-existent key
        assert await cache.delete("nonexistent") is False
        
        # Remaining keys should still exist
        assert await cache.get("key1") == "value1"
        assert await cache.get("key3") == "value3"
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_clear_cache(self):
        """Test clearing the cache."""
        cache = LRUCache(CacheConfig(max_size=10))
        
        # Add items
        for i in range(5):
            await cache.set(f"key{i}", f"value{i}")
        
        # Clear cache
        await cache.clear()
        
        # All items should be gone
        for i in range(5):
            assert await cache.get(f"key{i}") is None
        
        stats = await cache.get_stats()
        assert stats.size == 0
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_cache_stats(self):
        """Test cache statistics tracking."""
        cache = LRUCache(CacheConfig(max_size=3))
        
        # Initial stats
        stats = await cache.get_stats()
        assert stats.hits == 0
        assert stats.misses == 0
        assert stats.evictions == 0
        
        # Add items
        await cache.set("key1", "value1")
        await cache.set("key2", "value2")
        
        # Generate hits and misses
        assert await cache.get("key1") == "value1"  # Hit
        assert await cache.get("key1") == "value1"  # Hit
        assert await cache.get("key3") is None      # Miss
        
        # Fill cache and trigger eviction
        await cache.set("key3", "value3")
        await cache.set("key4", "value4")  # Should evict key2
        
        stats = await cache.get_stats()
        assert stats.hits == 2
        assert stats.misses == 1
        assert stats.evictions == 1
        assert stats.size == 3
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_delete_pattern(self):
        """Test pattern-based deletion."""
        cache = LRUCache(CacheConfig(max_size=10))
        
        # Add items with patterns
        await cache.set("user:1:profile", "profile1")
        await cache.set("user:1:settings", "settings1")
        await cache.set("user:2:profile", "profile2")
        await cache.set("post:1", "post1")
        
        # Delete by pattern
        deleted = await cache.delete_pattern("user:1:*")
        assert deleted == 2
        
        # Verify deletions
        assert await cache.get("user:1:profile") is None
        assert await cache.get("user:1:settings") is None
        assert await cache.get("user:2:profile") == "profile2"
        assert await cache.get("post:1") == "post1"
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_concurrent_access(self):
        """Test concurrent access to LRU cache."""
        cache = LRUCache(CacheConfig(max_size=100))
        
        async def writer(start: int, count: int):
            for i in range(start, start + count):
                await cache.set(f"key{i}", f"value{i}")
        
        async def reader(start: int, count: int):
            hits = 0
            for i in range(start, start + count):
                if await cache.get(f"key{i}") is not None:
                    hits += 1
            return hits
        
        # Concurrent writes
        await asyncio.gather(
            writer(0, 25),
            writer(25, 25),
            writer(50, 25),
            writer(75, 25)
        )
        
        # Concurrent reads
        hits = await asyncio.gather(
            reader(0, 25),
            reader(25, 25),
            reader(50, 25),
            reader(75, 25)
        )
        
        # All reads should hit
        assert sum(hits) == 100
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_memory_ordering(self):
        """Test that memory ordering is maintained correctly."""
        cache = LRUCache(CacheConfig(max_size=5))
        
        # Add items
        for i in range(5):
            await cache.set(f"key{i}", f"value{i}")
        
        # Access in specific order
        for i in [2, 4, 1, 3, 0]:
            await cache.get(f"key{i}")
        
        # Add new items to trigger evictions
        await cache.set("key5", "value5")
        await cache.set("key6", "value6")
        
        # Keys 2 and 4 should be evicted (accessed first)
        assert await cache.get("key2") is None
        assert await cache.get("key4") is None
        
        # Others should remain
        assert await cache.get("key1") == "value1"
        assert await cache.get("key3") == "value3"
        assert await cache.get("key0") == "value0"
        
        await cache.close()
    
    @pytest.mark.asyncio
    async def test_exists_updates_lru(self):
        """Test that exists() check updates LRU order."""
        cache = LRUCache(CacheConfig(max_size=3))
        
        # Fill cache
        await cache.set("key1", "value1")
        await cache.set("key2", "value2")
        await cache.set("key3", "value3")
        
        # Check existence of key1 (should update LRU)
        assert await cache.exists("key1") is True
        
        # Add new key - should evict key2 (least recently used)
        await cache.set("key4", "value4")
        
        assert await cache.get("key1") == "value1"  # Still exists (was checked)
        assert await cache.get("key2") is None      # Evicted
        assert await cache.get("key3") == "value3"  # Still exists
        
        await cache.close()