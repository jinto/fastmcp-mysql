"""Rate limiter interface for clean architecture."""

from abc import ABC, abstractmethod
from typing import Optional, Tuple


class RateLimiter(ABC):
    """Abstract base class for rate limiters."""
    
    @abstractmethod
    async def check_limit(self, identifier: str, resource: str = "query") -> Tuple[bool, Optional[int]]:
        """
        Check if a request is within rate limits.
        
        Args:
            identifier: Unique identifier (user_id, IP, etc.)
            resource: Resource being accessed
            
        Returns:
            Tuple of (is_allowed, retry_after_seconds)
            If allowed, retry_after_seconds is None
        """
        pass
    
    @abstractmethod
    async def record_request(self, identifier: str, resource: str = "query", cost: int = 1) -> None:
        """
        Record a request for rate limiting.
        
        Args:
            identifier: Unique identifier
            resource: Resource being accessed
            cost: Cost of the request (for weighted rate limiting)
        """
        pass