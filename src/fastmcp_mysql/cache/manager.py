"""Cache manager for coordinating cache operations."""
import logging
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

from .interfaces import CacheInterface, CacheConfig, CacheStats, CacheKeyGenerator
from .ttl_cache import TTLCache
from .lru_cache import LRUCache
from .invalidator import CacheInvalidator, InvalidationStrategy, QueryType


logger = logging.getLogger(__name__)


class CacheManager:
    """Manages caching for MySQL queries.
    
    Coordinates between cache implementations, key generation,
    and invalidation strategies.
    """
    
    def __init__(self, config: CacheConfig):
        """Initialize cache manager.
        
        Args:
            config: Cache configuration
        """
        self.config = config
        self.enabled = config.enabled
        
        # Initialize cache based on eviction policy
        self.cache: Optional[CacheInterface] = None
        if self.enabled:
            if config.eviction_policy == "lru":
                self.cache = LRUCache(config)
            else:  # Default to TTL cache
                self.cache = TTLCache(config)
        
        # Initialize components
        self.key_generator = CacheKeyGenerator()
        self.invalidator = CacheInvalidator(
            strategy=InvalidationStrategy(config.invalidation_mode)
        )
        
        # Statistics
        self._query_count = 0
        self._cache_hits = 0
        self._cache_misses = 0
    
    def is_cacheable_query(self, query: str) -> bool:
        """Check if a query should be cached.
        
        Args:
            query: SQL query
            
        Returns:
            True if query should be cached
        """
        if not self.enabled:
            return False
        
        # Only cache SELECT queries
        query_type = self.invalidator.get_query_type(query)
        return query_type == QueryType.SELECT
    
    async def get_cached_result(
        self,
        query: str,
        params: Optional[Tuple[Any, ...]] = None,
        database: Optional[str] = None
    ) -> Optional[Any]:
        """Get cached query result.
        
        Args:
            query: SQL query
            params: Query parameters
            database: Database name
            
        Returns:
            Cached result or None if not found
        """
        if not self.enabled or not self.cache:
            return None
        
        if not self.is_cacheable_query(query):
            return None
        
        # Generate cache key
        cache_key = self.key_generator.generate_key(query, params, database)
        
        # Get from cache
        result = await self.cache.get(cache_key)
        
        # Update statistics
        self._query_count += 1
        if result is not None:
            self._cache_hits += 1
            logger.debug(f"Cache hit for key: {cache_key}")
        else:
            self._cache_misses += 1
            logger.debug(f"Cache miss for key: {cache_key}")
        
        return result
    
    async def cache_result(
        self,
        query: str,
        result: Any,
        params: Optional[Tuple[Any, ...]] = None,
        database: Optional[str] = None,
        ttl: Optional[int] = None
    ) -> None:
        """Cache a query result.
        
        Args:
            query: SQL query
            result: Query result to cache
            params: Query parameters
            database: Database name
            ttl: Optional TTL override
        """
        if not self.enabled or not self.cache:
            return
        
        if not self.is_cacheable_query(query):
            return
        
        # Generate cache key
        cache_key = self.key_generator.generate_key(query, params, database)
        
        # Store in cache
        await self.cache.set(cache_key, result, ttl)
        logger.debug(f"Cached result for key: {cache_key}")
    
    async def invalidate_on_write(
        self,
        query: str,
        database: Optional[str] = None
    ) -> None:
        """Invalidate cache entries affected by a write operation.
        
        Args:
            query: Write query (INSERT/UPDATE/DELETE)
            database: Database name
        """
        if not self.enabled or not self.cache:
            return
        
        await self.invalidator.invalidate_on_write(
            query, self.cache, database
        )
        logger.debug(f"Invalidated cache for query: {query[:50]}...")
    
    async def invalidate_batch(
        self,
        queries: List[str],
        database: Optional[str] = None
    ) -> None:
        """Invalidate cache for a batch of queries.
        
        Args:
            queries: List of queries
            database: Database name
        """
        if not self.enabled or not self.cache:
            return
        
        await self.invalidator.invalidate_batch(
            queries, self.cache, database
        )
    
    def add_table_dependency(self, table: str, depends_on: List[str]) -> None:
        """Add table dependencies for invalidation.
        
        Args:
            table: Table name
            depends_on: List of tables this table depends on
        """
        self.invalidator.add_dependency(table, depends_on)
    
    async def clear_cache(self) -> None:
        """Clear all cache entries."""
        if self.cache:
            await self.cache.clear()
            logger.info("Cache cleared")
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        cache_stats = None
        if self.cache:
            cache_stats = await self.cache.get_stats()
        
        manager_stats = {
            "enabled": self.enabled,
            "eviction_policy": self.config.eviction_policy,
            "query_count": self._query_count,
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "hit_rate": self._cache_hits / self._query_count if self._query_count > 0 else 0.0
        }
        
        if cache_stats:
            manager_stats.update({
                "cache_size": cache_stats.size,
                "cache_max_size": cache_stats.max_size,
                "cache_evictions": cache_stats.evictions,
                "cache_utilization": cache_stats.utilization
            })
        
        return manager_stats
    
    async def close(self) -> None:
        """Close cache manager and clean up resources."""
        if self.cache:
            await self.cache.close()
            logger.info("Cache manager closed")
    
    async def warm_cache(
        self,
        queries: List[Tuple[str, Optional[Tuple[Any, ...]], Any]],
        database: Optional[str] = None
    ) -> None:
        """Warm up cache with pre-computed results.
        
        Args:
            queries: List of (query, params, result) tuples
            database: Database name
        """
        if not self.enabled:
            return
        
        for query, params, result in queries:
            await self.cache_result(query, result, params, database)
        
        logger.info(f"Warmed cache with {len(queries)} entries")
    
    def get_cache_key(
        self,
        query: str,
        params: Optional[Tuple[Any, ...]] = None,
        database: Optional[str] = None
    ) -> str:
        """Get the cache key for a query (for debugging).
        
        Args:
            query: SQL query
            params: Query parameters
            database: Database name
            
        Returns:
            Cache key
        """
        return self.key_generator.generate_key(query, params, database)