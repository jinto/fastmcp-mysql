"""Fixed window rate limiter implementation."""

import asyncio
import time
from typing import Dict
from dataclasses import dataclass

from ..interfaces import RateLimiter


@dataclass
class WindowCounter:
    """Counter for fixed window."""
    count: int
    window_start: float


class FixedWindowLimiter(RateLimiter):
    """Fixed window rate limiter."""
    
    def __init__(self, requests_per_minute: int):
        """
        Initialize fixed window limiter.
        
        Args:
            requests_per_minute: Requests allowed per minute
        """
        self.requests_per_minute = requests_per_minute
        self.window_size = 60.0  # 60 seconds window
        self.counters: Dict[str, WindowCounter] = {}
        self._lock = asyncio.Lock()
    
    def _get_current_window(self, current_time: float) -> float:
        """Get start time of current window."""
        return (current_time // self.window_size) * self.window_size
    
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
            current_window = self._get_current_window(current_time)
            
            # Get or create counter
            if identifier not in self.counters:
                self.counters[identifier] = WindowCounter(0, current_window)
            
            counter = self.counters[identifier]
            
            # Reset counter if in new window
            if counter.window_start < current_window:
                counter.count = 0
                counter.window_start = current_window
            
            # Check if under limit
            if counter.count < self.requests_per_minute:
                counter.count += 1
                return True
            
            return False
    
    async def reset(self, identifier: str) -> None:
        """
        Reset rate limit for identifier.
        
        Args:
            identifier: User identifier to reset
        """
        async with self._lock:
            if identifier in self.counters:
                del self.counters[identifier]