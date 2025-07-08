"""Rate limiter interface for clean architecture."""

from abc import ABC, abstractmethod


class RateLimiter(ABC):
    """Abstract base class for rate limiters."""
    
    @abstractmethod
    async def check_limit(self, identifier: str) -> bool:
        """
        Check if a request is within rate limits.
        
        Args:
            identifier: Unique identifier (user_id, IP, etc.)
            
        Returns:
            True if allowed, False if rate limited
        """
        pass
    
    @abstractmethod
    async def reset(self, identifier: str) -> None:
        """
        Reset rate limit for an identifier.
        
        Args:
            identifier: Unique identifier to reset
        """
        pass