"""Cache module for FastMCP MySQL Server."""
from .interfaces import (
    CacheInterface,
    CacheEntry,
    CacheStats,
    CacheKeyGenerator,
    CacheConfig
)
from .ttl_cache import TTLCache
from .lru_cache import LRUCache
from .invalidator import (
    CacheInvalidator,
    InvalidationStrategy,
    QueryType,
    TableDependency
)
from .manager import CacheManager

__all__ = [
    "CacheInterface",
    "CacheEntry",
    "CacheStats",
    "CacheKeyGenerator",
    "CacheConfig",
    "TTLCache",
    "LRUCache",
    "CacheInvalidator",
    "InvalidationStrategy",
    "QueryType",
    "TableDependency",
    "CacheManager"
]