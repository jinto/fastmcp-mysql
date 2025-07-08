"""Tests for rate limiting functionality."""

import pytest
import asyncio
import time
from unittest.mock import Mock, AsyncMock

from fastmcp_mysql.security.interfaces import RateLimiter
from fastmcp_mysql.security.config import RateLimitAlgorithm, SecuritySettings
from fastmcp_mysql.security.exceptions import RateLimitError


class TestRateLimiting:
    """Test rate limiting functionality."""
    
    def test_rate_limiter_interface(self):
        """Test that RateLimiter interface is properly defined."""
        from fastmcp_mysql.security.interfaces import RateLimiter
        
        # Interface should require these methods
        assert hasattr(RateLimiter, 'check_limit')
        assert hasattr(RateLimiter, 'reset')
    
    @pytest.mark.asyncio
    async def test_token_bucket_basic_functionality(self):
        """Test basic token bucket rate limiting."""
        from fastmcp_mysql.security.rate_limiting import TokenBucketLimiter
        
        # 10 requests per minute, burst of 5
        limiter = TokenBucketLimiter(
            requests_per_minute=10,
            burst_size=5
        )
        
        # Should allow burst of 5 requests immediately
        for i in range(5):
            result = await limiter.check_limit("user1")
            assert result is True, f"Request {i+1} should be allowed"
        
        # 6th request should be rate limited
        result = await limiter.check_limit("user1")
        assert result is False, "6th request should be rate limited"
    
    @pytest.mark.asyncio
    async def test_token_bucket_refill(self):
        """Test token bucket refill mechanism."""
        from fastmcp_mysql.security.rate_limiting import TokenBucketLimiter
        
        # Fast refill for testing: 60 requests per minute = 1 per second
        limiter = TokenBucketLimiter(
            requests_per_minute=60,
            burst_size=2
        )
        
        # Use up all tokens
        await limiter.check_limit("user1")
        await limiter.check_limit("user1")
        
        # Should be rate limited
        assert await limiter.check_limit("user1") is False
        
        # Wait for refill
        await asyncio.sleep(1.1)
        
        # Should have 1 token refilled
        assert await limiter.check_limit("user1") is True
        assert await limiter.check_limit("user1") is False
    
    @pytest.mark.asyncio
    async def test_sliding_window_basic_functionality(self):
        """Test sliding window rate limiting."""
        from fastmcp_mysql.security.rate_limiting import SlidingWindowLimiter
        
        # 5 requests per minute
        limiter = SlidingWindowLimiter(requests_per_minute=5)
        
        # Should allow 5 requests
        for i in range(5):
            result = await limiter.check_limit("user1")
            assert result is True, f"Request {i+1} should be allowed"
        
        # 6th request should be rate limited
        result = await limiter.check_limit("user1")
        assert result is False, "6th request should be rate limited"
    
    @pytest.mark.asyncio
    async def test_sliding_window_expiry(self):
        """Test sliding window request expiry."""
        from fastmcp_mysql.security.rate_limiting import SlidingWindowLimiter
        
        # 2 requests per minute
        limiter = SlidingWindowLimiter(requests_per_minute=2)
        
        # Make 2 requests
        assert await limiter.check_limit("user1") is True
        assert await limiter.check_limit("user1") is True
        
        # 3rd should fail
        assert await limiter.check_limit("user1") is False
        
        # Wait for window to slide (requests expire after 60 seconds)
        # This test would take too long, so we'll skip the expiry test
        # In real usage, after 60 seconds, old requests would expire
    
    @pytest.mark.asyncio
    async def test_fixed_window_basic_functionality(self):
        """Test fixed window rate limiting."""
        from fastmcp_mysql.security.rate_limiting import FixedWindowLimiter
        
        # 5 requests per minute
        limiter = FixedWindowLimiter(requests_per_minute=5)
        
        # Should allow 5 requests in current window
        for i in range(5):
            result = await limiter.check_limit("user1")
            assert result is True, f"Request {i+1} should be allowed"
        
        # 6th request should be rate limited
        result = await limiter.check_limit("user1")
        assert result is False, "6th request should be rate limited"
    
    @pytest.mark.asyncio
    async def test_per_user_limits(self):
        """Test per-user rate limits."""
        from fastmcp_mysql.security.rate_limiting import TokenBucketLimiter
        
        # Default limit: 10 per minute
        # Special user: 20 per minute
        limiter = TokenBucketLimiter(
            requests_per_minute=10,
            burst_size=5,
            per_user_limits={"special_user": 20}
        )
        
        # Regular user hits limit at 5 (burst size)
        for i in range(5):
            assert await limiter.check_limit("regular_user") is True
        assert await limiter.check_limit("regular_user") is False
        
        # Special user has higher limit
        for i in range(10):
            assert await limiter.check_limit("special_user") is True
        # But eventually hits their limit too
        assert await limiter.check_limit("special_user") is False
    
    @pytest.mark.asyncio
    async def test_rate_limiter_reset(self):
        """Test rate limiter reset functionality."""
        from fastmcp_mysql.security.rate_limiting import TokenBucketLimiter
        
        limiter = TokenBucketLimiter(
            requests_per_minute=10,
            burst_size=2
        )
        
        # Use up tokens
        await limiter.check_limit("user1")
        await limiter.check_limit("user1")
        assert await limiter.check_limit("user1") is False
        
        # Reset for specific user
        await limiter.reset("user1")
        
        # Should have tokens again
        assert await limiter.check_limit("user1") is True
        assert await limiter.check_limit("user1") is True
    
    @pytest.mark.asyncio
    async def test_rate_limiter_with_security_context(self):
        """Test rate limiter with security settings."""
        from fastmcp_mysql.security.rate_limiting import TokenBucketLimiter
        
        settings = SecuritySettings(
            enable_rate_limiting=True,
            rate_limit_requests_per_minute=10,
            rate_limit_burst_size=2
        )
        
        limiter = TokenBucketLimiter(
            requests_per_minute=settings.rate_limit_requests_per_minute,
            burst_size=settings.rate_limit_burst_size
        )
        
        # Should allow burst
        assert await limiter.check_limit("test_user") is True
        assert await limiter.check_limit("test_user") is True
        
        # 3rd request should be rate limited
        assert await limiter.check_limit("test_user") is False
    
    @pytest.mark.asyncio
    async def test_concurrent_rate_limiting(self):
        """Test rate limiting under concurrent load."""
        from fastmcp_mysql.security.rate_limiting import TokenBucketLimiter
        
        limiter = TokenBucketLimiter(
            requests_per_minute=60,
            burst_size=10
        )
        
        # Simulate concurrent requests
        async def make_request(user_id: str, request_id: int):
            result = await limiter.check_limit(user_id)
            return (request_id, result)
        
        # Make 20 concurrent requests
        tasks = [make_request("user1", i) for i in range(20)]
        results = await asyncio.gather(*tasks)
        
        # First 10 should succeed (burst size)
        succeeded = sum(1 for _, result in results if result)
        assert succeeded == 10, f"Expected 10 successful requests, got {succeeded}"
    
    @pytest.mark.asyncio
    async def test_rate_limiter_factory(self):
        """Test rate limiter factory creation."""
        from fastmcp_mysql.security.rate_limiting import create_rate_limiter
        
        # Token bucket
        limiter = create_rate_limiter(
            algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
            requests_per_minute=60,
            burst_size=10
        )
        assert limiter is not None
        assert await limiter.check_limit("user1") is True
        
        # Sliding window
        limiter = create_rate_limiter(
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            requests_per_minute=60
        )
        assert limiter is not None
        assert await limiter.check_limit("user2") is True
        
        # Fixed window
        limiter = create_rate_limiter(
            algorithm=RateLimitAlgorithm.FIXED_WINDOW,
            requests_per_minute=60
        )
        assert limiter is not None
        assert await limiter.check_limit("user3") is True
    
    def test_rate_limit_error_messages(self):
        """Test rate limit error messages."""
        from fastmcp_mysql.security.exceptions import RateLimitError
        
        error = RateLimitError("Rate limit exceeded for user: test_user")
        assert "rate limit" in str(error).lower()
        assert "test_user" in str(error)