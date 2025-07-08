"""Token bucket rate limiter implementation."""

import asyncio
import time
from typing import Dict, Optional
from dataclasses import dataclass, field

from ..interfaces import RateLimiter


@dataclass
class TokenBucket:
    """Token bucket for rate limiting."""
    capacity: int
    tokens: float
    refill_rate: float
    last_refill: float
    
    def refill(self, current_time: float) -> None:
        """Refill tokens based on elapsed time."""
        elapsed = current_time - self.last_refill
        tokens_to_add = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill = current_time
    
    def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens."""
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False


class TokenBucketLimiter(RateLimiter):
    """Token bucket rate limiter."""
    
    def __init__(
        self,
        requests_per_minute: int,
        burst_size: int,
        per_user_limits: Optional[Dict[str, int]] = None
    ):
        """
        Initialize token bucket limiter.
        
        Args:
            requests_per_minute: Requests allowed per minute
            burst_size: Maximum burst size
            per_user_limits: Per-user rate limits
        """
        self.default_rpm = requests_per_minute
        self.burst_size = burst_size
        self.per_user_limits = per_user_limits or {}
        self.buckets: Dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()
    
    def _get_or_create_bucket(self, identifier: str) -> TokenBucket:
        """Get or create bucket for identifier."""
        if identifier not in self.buckets:
            # Check for custom limit
            rpm = self.per_user_limits.get(identifier, self.default_rpm)
            refill_rate = rpm / 60.0  # Tokens per second
            
            # For special users with higher limits, scale burst size proportionally
            if identifier in self.per_user_limits:
                burst = int(self.burst_size * (rpm / self.default_rpm))
            else:
                burst = self.burst_size
            
            self.buckets[identifier] = TokenBucket(
                capacity=burst,
                tokens=burst,
                refill_rate=refill_rate,
                last_refill=time.time()
            )
        return self.buckets[identifier]
    
    async def check_limit(self, identifier: str) -> bool:
        """
        Check if request is within rate limit.
        
        Args:
            identifier: User identifier
            
        Returns:
            True if allowed, False if rate limited
        """
        async with self._lock:
            current_time = time.time()
            bucket = self._get_or_create_bucket(identifier)
            
            # Refill tokens
            bucket.refill(current_time)
            
            # Try to consume token
            return bucket.consume()
    
    async def reset(self, identifier: str) -> None:
        """
        Reset rate limit for identifier.
        
        Args:
            identifier: User identifier to reset
        """
        async with self._lock:
            if identifier in self.buckets:
                del self.buckets[identifier]