"""Cache interfaces and base classes."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
import hashlib
import re
import os


@dataclass
class CacheEntry:
    """Represents a single cache entry."""
    key: str
    value: Any
    created_at: datetime
    expires_at: Optional[datetime]
    hit_count: int = 0
    
    def is_expired(self) -> bool:
        """Check if the cache entry has expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at
    
    def remaining_ttl(self) -> Optional[float]:
        """Get remaining TTL in seconds."""
        if self.expires_at is None:
            return None
        remaining = (self.expires_at - datetime.now()).total_seconds()
        return max(0, remaining)


@dataclass
class CacheStats:
    """Cache statistics."""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    size: int = 0
    max_size: int = 1000
    
    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self.hits + self.misses
        if total == 0:
            return 0.0
        return self.hits / total
    
    @property
    def utilization(self) -> float:
        """Calculate cache utilization."""
        if self.max_size == 0:
            return 0.0
        return self.size / self.max_size
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "size": self.size,
            "max_size": self.max_size,
            "hit_rate": self.hit_rate,
            "utilization": self.utilization
        }


@dataclass
class CacheConfig:
    """Cache configuration."""
    enabled: bool = True
    ttl: int = 300  # Default 5 minutes
    max_size: int = 1000
    eviction_policy: str = "lru"  # lru, lfu, fifo
    cleanup_interval: float = 60.0  # Cleanup interval in seconds
    
    # Memory cache settings
    memory_enabled: bool = True
    memory_max_size: int = 1000
    memory_ttl: int = 300
    
    # Redis cache settings (future)
    redis_enabled: bool = False
    redis_url: Optional[str] = None
    redis_ttl: int = 3600
    redis_prefix: str = "fastmcp:mysql:"
    
    # Cache invalidation settings
    invalidation_mode: str = "aggressive"  # aggressive, conservative
    tag_enabled: bool = True
    
    # Statistics
    stats_enabled: bool = True
    
    @classmethod
    def from_env(cls) -> "CacheConfig":
        """Create configuration from environment variables."""
        return cls(
            enabled=os.getenv("MYSQL_CACHE_ENABLED", "true").lower() == "true",
            ttl=int(os.getenv("MYSQL_CACHE_TTL", "300")),
            max_size=int(os.getenv("MYSQL_CACHE_MAX_SIZE", "1000")),
            eviction_policy=os.getenv("MYSQL_CACHE_EVICTION_POLICY", "lru"),
            
            memory_enabled=os.getenv("MYSQL_CACHE_MEMORY_ENABLED", "true").lower() == "true",
            memory_max_size=int(os.getenv("MYSQL_CACHE_MEMORY_MAX_SIZE", "1000")),
            memory_ttl=int(os.getenv("MYSQL_CACHE_MEMORY_TTL", "300")),
            
            redis_enabled=os.getenv("MYSQL_CACHE_REDIS_ENABLED", "false").lower() == "true",
            redis_url=os.getenv("MYSQL_CACHE_REDIS_URL"),
            redis_ttl=int(os.getenv("MYSQL_CACHE_REDIS_TTL", "3600")),
            redis_prefix=os.getenv("MYSQL_CACHE_REDIS_PREFIX", "fastmcp:mysql:"),
            
            invalidation_mode=os.getenv("MYSQL_CACHE_INVALIDATION_MODE", "aggressive"),
            tag_enabled=os.getenv("MYSQL_CACHE_TAG_ENABLED", "true").lower() == "true",
            
            stats_enabled=os.getenv("MYSQL_CACHE_STATS_ENABLED", "true").lower() == "true"
        )


class CacheKeyGenerator:
    """Generates cache keys for queries."""
    
    def __init__(self, prefix: str = ""):
        self.prefix = prefix
    
    def normalize_query(self, query: str) -> str:
        """Normalize SQL query for consistent cache keys."""
        # Remove extra whitespace
        normalized = re.sub(r'\s+', ' ', query.strip())
        
        # Convert to lowercase for consistency
        normalized = normalized.lower()
        
        # Remove comments
        normalized = re.sub(r'/\*.*?\*/', '', normalized)
        normalized = re.sub(r'--.*$', '', normalized, flags=re.MULTILINE)
        
        return normalized
    
    def generate_key(
        self,
        query: str,
        params: Optional[Tuple[Any, ...]] = None,
        database: Optional[str] = None
    ) -> str:
        """Generate a cache key for a query."""
        # Normalize the query
        normalized_query = self.normalize_query(query)
        
        # Create a unique key
        components = []
        
        # Add prefix if set
        if self.prefix:
            components.append(self.prefix)
        
        # Add database if specified
        if database:
            components.append(database)
        
        # Hash the query
        query_hash = hashlib.sha256(normalized_query.encode()).hexdigest()[:16]
        components.append(query_hash)
        
        # Hash the parameters if provided
        if params:
            params_str = str(params)
            params_hash = hashlib.sha256(params_str.encode()).hexdigest()[:8]
            components.append(params_hash)
        else:
            components.append("noparams")
        
        return ":".join(components)
    
    def extract_tables(self, query: str) -> List[str]:
        """Extract table names from a query for invalidation."""
        tables = []
        normalized = self.normalize_query(query)
        
        # Simple regex patterns for table extraction
        # This is a basic implementation - could be improved with SQL parser
        patterns = [
            r'from\s+(\w+)',
            r'join\s+(\w+)',
            r'into\s+(\w+)',
            r'update\s+(\w+)',
            r'delete\s+from\s+(\w+)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, normalized, re.IGNORECASE)
            tables.extend(matches)
        
        # Remove duplicates and return
        return list(set(tables))


class CacheInterface(ABC):
    """Abstract base class for cache implementations."""
    
    @abstractmethod
    async def get(self, key: str) -> Optional[Any]:
        """Get a value from the cache."""
        pass
    
    @abstractmethod
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set a value in the cache with optional TTL."""
        pass
    
    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete a key from the cache."""
        pass
    
    @abstractmethod
    async def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching a pattern."""
        pass
    
    @abstractmethod
    async def clear(self) -> None:
        """Clear all entries from the cache."""
        pass
    
    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if a key exists in the cache."""
        pass
    
    @abstractmethod
    async def get_stats(self) -> CacheStats:
        """Get cache statistics."""
        pass
    
    @abstractmethod
    async def close(self) -> None:
        """Close the cache and clean up resources."""
        pass
    
    async def get_many(self, keys: List[str]) -> Dict[str, Any]:
        """Get multiple values from the cache."""
        result = {}
        for key in keys:
            value = await self.get(key)
            if value is not None:
                result[key] = value
        return result
    
    async def set_many(self, items: Dict[str, Any], ttl: Optional[int] = None) -> None:
        """Set multiple values in the cache."""
        for key, value in items.items():
            await self.set(key, value, ttl)
    
    async def increment(self, key: str, delta: int = 1) -> int:
        """Increment a numeric value in the cache."""
        value = await self.get(key)
        if value is None:
            value = 0
        elif not isinstance(value, (int, float)):
            raise ValueError(f"Cannot increment non-numeric value: {value}")
        
        new_value = value + delta
        await self.set(key, new_value)
        return new_value