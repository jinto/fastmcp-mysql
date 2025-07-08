"""Sliding window rate limiter implementation."""

import asyncio
import time
from typing import Dict, List
from collections import deque

from ..interfaces import RateLimiter


class SlidingWindowLimiter(RateLimiter):
    """Sliding window rate limiter."""
    
    def __init__(self, requests_per_minute: int):
        """
        Initialize sliding window limiter.
        
        Args:
            requests_per_minute: Requests allowed per minute
        """
        self.requests_per_minute = requests_per_minute
        self.window_size = 60.0  # 60 seconds window
        self.requests: Dict[str, deque] = {}
        self._lock = asyncio.Lock()
    
    def _clean_old_requests(self, timestamps: deque, current_time: float) -> None:
        """Remove requests older than window size."""
        cutoff = current_time - self.window_size
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()
    
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
            
            # Get or create request queue
            if identifier not in self.requests:
                self.requests[identifier] = deque()
            
            timestamps = self.requests[identifier]
            
            # Clean old requests
            self._clean_old_requests(timestamps, current_time)
            
            # Check if under limit
            if len(timestamps) < self.requests_per_minute:
                timestamps.append(current_time)
                return True
            
            return False
    
    async def reset(self, identifier: str) -> None:
        """
        Reset rate limit for identifier.
        
        Args:
            identifier: User identifier to reset
        """
        async with self._lock:
            if identifier in self.requests:
                del self.requests[identifier]