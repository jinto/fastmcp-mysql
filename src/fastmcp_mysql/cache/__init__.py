"""Cache module for FastMCP MySQL Server."""

from .interfaces import (
    CacheConfig,
    CacheEntry,
    CacheInterface,
    CacheKeyGenerator,
    CacheStats,
)
from .invalidator import (
    CacheInvalidator,
    InvalidationStrategy,
    QueryType,
    TableDependency,
)
from .lru_cache import LRUCache
from .manager import CacheManager
from .ttl_cache import TTLCache

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
    "CacheManager",
]
