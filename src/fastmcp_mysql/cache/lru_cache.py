"""LRU (Least Recently Used) cache implementation."""
import asyncio
import fnmatch
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from collections import OrderedDict

from .interfaces import CacheInterface, CacheEntry, CacheStats, CacheConfig


class LRUCache(CacheInterface):
    """Least Recently Used cache implementation.
    
    Features:
    - LRU eviction policy
    - TTL support
    - Thread-safe operations
    - Pattern-based deletion
    - O(1) get/set operations
    """
    
    def __init__(self, config: CacheConfig):
        """Initialize LRU cache.
        
        Args:
            config: Cache configuration
        """
        self.config = config
        self.max_size = config.max_size
        self.default_ttl = config.ttl
        
        # Use OrderedDict for O(1) LRU operations
        self._storage: OrderedDict[str, CacheEntry] = OrderedDict()
        self._stats = CacheStats(
            hits=0,
            misses=0,
            evictions=0,
            size=0,
            max_size=self.max_size
        )
        
        # Lock for thread safety
        self._lock = asyncio.Lock()
        
        # Cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None
        self._cleanup_interval = config.cleanup_interval
        self._running = True
        
        # Start cleanup task if interval is positive
        if self._cleanup_interval > 0:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def _cleanup_loop(self):
        """Background task to clean up expired entries."""
        while self._running:
            try:
                await asyncio.sleep(self._cleanup_interval)
                await self._cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception:
                # Log error in production
                pass
    
    async def _cleanup_expired(self):
        """Remove expired entries from cache."""
        async with self._lock:
            expired_keys = []
            
            for key, entry in self._storage.items():
                if entry.is_expired():
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self._storage[key]
                self._stats.evictions += 1
            
            self._stats.size = len(self._storage)
    
    def _move_to_end(self, key: str):
        """Move key to end (most recently used) without lock."""
        # This is O(1) in Python 3.7+ OrderedDict
        self._storage.move_to_end(key)
    
    async def _evict_if_needed(self):
        """Evict entries if cache is full (LRU policy)."""
        # First, clean up expired entries
        expired_keys = []
        for key, entry in self._storage.items():
            if entry.is_expired():
                expired_keys.append(key)
        
        for key in expired_keys:
            del self._storage[key]
            self._stats.evictions += 1
        
        # Then evict LRU entries if still needed
        while len(self._storage) >= self.max_size:
            # Remove least recently used (first item)
            if self._storage:
                lru_key = next(iter(self._storage))
                del self._storage[lru_key]
                self._stats.evictions += 1
    
    async def get(self, key: str) -> Optional[Any]:
        """Get a value from the cache."""
        async with self._lock:
            entry = self._storage.get(key)
            
            if entry is None:
                self._stats.misses += 1
                return None
            
            if entry.is_expired():
                # Remove expired entry
                del self._storage[key]
                self._stats.misses += 1
                self._stats.size = len(self._storage)
                return None
            
            # Update hit count and stats
            entry.hit_count += 1
            self._stats.hits += 1
            
            # Move to end (most recently used)
            self._move_to_end(key)
            
            return entry.value
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set a value in the cache with optional TTL."""
        async with self._lock:
            # Use provided TTL or default
            if ttl is None:
                ttl = self.default_ttl
            
            # Calculate expiration time
            expires_at = None
            if ttl is not None and ttl >= 0:
                expires_at = datetime.now() + timedelta(seconds=ttl)
            elif ttl is not None and ttl < 0:
                # Negative TTL means already expired
                expires_at = datetime.now() - timedelta(seconds=1)
            
            # Check if key already exists
            existing = key in self._storage
            
            # Evict if needed (only if adding new key)
            if not existing:
                await self._evict_if_needed()
            
            # Create entry
            entry = CacheEntry(
                key=key,
                value=value,
                created_at=datetime.now(),
                expires_at=expires_at,
                hit_count=0
            )
            
            # Store entry
            self._storage[key] = entry
            
            # Move to end (most recently used)
            self._move_to_end(key)
            
            self._stats.size = len(self._storage)
    
    async def delete(self, key: str) -> bool:
        """Delete a key from the cache."""
        async with self._lock:
            if key in self._storage:
                del self._storage[key]
                self._stats.size = len(self._storage)
                return True
            return False
    
    async def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching a pattern."""
        async with self._lock:
            keys_to_delete = []
            
            # Find matching keys
            for key in self._storage:
                if fnmatch.fnmatch(key, pattern):
                    keys_to_delete.append(key)
            
            # Delete matching keys
            for key in keys_to_delete:
                del self._storage[key]
            
            self._stats.size = len(self._storage)
            return len(keys_to_delete)
    
    async def clear(self) -> None:
        """Clear all entries from the cache."""
        async with self._lock:
            self._stats.evictions += len(self._storage)
            self._storage.clear()
            self._stats.size = 0
    
    async def exists(self, key: str) -> bool:
        """Check if a key exists in the cache."""
        async with self._lock:
            entry = self._storage.get(key)
            if entry is None:
                return False
            
            if entry.is_expired():
                # Remove expired entry
                del self._storage[key]
                self._stats.size = len(self._storage)
                return False
            
            # Move to end (most recently used) - important for LRU
            self._move_to_end(key)
            
            return True
    
    async def get_stats(self) -> CacheStats:
        """Get cache statistics."""
        async with self._lock:
            return CacheStats(
                hits=self._stats.hits,
                misses=self._stats.misses,
                evictions=self._stats.evictions,
                size=len(self._storage),
                max_size=self.max_size
            )
    
    async def close(self) -> None:
        """Close the cache and clean up resources."""
        self._running = False
        
        # Cancel cleanup task
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Clear cache
        await self.clear()
    
    async def get_lru_order(self) -> List[str]:
        """Get keys in LRU order (for debugging/testing)."""
        async with self._lock:
            return list(self._storage.keys())