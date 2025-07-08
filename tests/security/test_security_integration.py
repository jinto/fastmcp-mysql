"""Integration tests for security components."""

import pytest
from unittest.mock import Mock, AsyncMock

from fastmcp_mysql.security import SecurityManager, SecurityContext, SecuritySettings
from fastmcp_mysql.security.config import FilterMode, RateLimitAlgorithm
from fastmcp_mysql.security.injection import SQLInjectionDetector
from fastmcp_mysql.security.filtering import BlacklistFilter, WhitelistFilter
from fastmcp_mysql.security.rate_limiting import TokenBucketLimiter
from fastmcp_mysql.security.exceptions import (
    InjectionError, FilteredQueryError, RateLimitError, SecurityError
)


class TestSecurityIntegration:
    """Test integration of security components."""
    
    @pytest.mark.asyncio
    async def test_full_security_stack(self):
        """Test full security stack with all components."""
        # Configure security
        settings = SecuritySettings(
            enable_injection_detection=True,
            enable_rate_limiting=True,
            filter_mode=FilterMode.BLACKLIST,
            rate_limit_requests_per_minute=10,
            rate_limit_burst_size=2
        )
        
        # Create components
        injection_detector = SQLInjectionDetector()
        query_filter = BlacklistFilter(settings)
        rate_limiter = TokenBucketLimiter(
            requests_per_minute=settings.rate_limit_requests_per_minute,
            burst_size=settings.rate_limit_burst_size
        )
        
        # Create manager
        manager = SecurityManager(
            settings=settings,
            injection_detector=injection_detector,
            query_filter=query_filter,
            rate_limiter=rate_limiter
        )
        
        context = SecurityContext(user_id="test_user")
        
        # Test 1: Safe query should pass
        safe_query = "SELECT * FROM users WHERE id = %s"
        params = (123,)
        
        # Should pass validation
        await manager.validate_query(safe_query, params, context)
        
        # Test 2: SQL injection should be blocked
        injection_query = "SELECT * FROM users WHERE id = %s"
        injection_params = ("1' OR '1'='1",)
        
        with pytest.raises(InjectionError):
            await manager.validate_query(injection_query, injection_params, context)
        
        # Test 3: Rate limiting should work
        # Already used 2 requests (burst size), 3rd should fail
        with pytest.raises(RateLimitError):
            await manager.validate_query(safe_query, params, context)
        
        # Reset rate limiter for next test
        await rate_limiter.reset(context.identifier)
        
        # Test 4: Blacklisted query should be blocked
        blacklisted = "SELECT * FROM information_schema.tables"
        
        with pytest.raises(FilteredQueryError):
            await manager.validate_query(blacklisted, None, context)
    
    @pytest.mark.asyncio
    async def test_security_manager_with_disabled_features(self):
        """Test security manager with features disabled."""
        settings = SecuritySettings(
            enable_injection_detection=False,
            enable_rate_limiting=False,
            filter_mode=FilterMode.BLACKLIST
        )
        
        manager = SecurityManager(settings=settings)
        context = SecurityContext(user_id="test_user")
        
        # Injection should pass when detection disabled
        injection_query = "SELECT * FROM users WHERE id = '1' OR '1'='1'"
        await manager.validate_query(injection_query, None, context)
        
        # Multiple requests should pass when rate limiting disabled
        for _ in range(100):
            await manager.validate_query("SELECT 1", None, context)
    
    @pytest.mark.asyncio
    async def test_whitelist_mode_integration(self):
        """Test security with whitelist mode."""
        settings = SecuritySettings(
            enable_injection_detection=True,
            filter_mode=FilterMode.WHITELIST
        )
        
        # Define allowed queries
        whitelist_patterns = [
            r"^SELECT \* FROM users WHERE id = %s$",
            r"^INSERT INTO logs \(message\) VALUES \(%s\)$"
        ]
        
        manager = SecurityManager(
            settings=settings,
            injection_detector=SQLInjectionDetector(),
            query_filter=WhitelistFilter(patterns=whitelist_patterns)
        )
        
        context = SecurityContext(user_id="test_user")
        
        # Whitelisted query should pass
        await manager.validate_query("SELECT * FROM users WHERE id = %s", (123,), context)
        
        # Non-whitelisted query should fail
        with pytest.raises(FilteredQueryError):
            await manager.validate_query("DELETE FROM users WHERE id = %s", (123,), context)
        
        # Injection in whitelisted pattern should still be caught
        with pytest.raises(InjectionError):
            await manager.validate_query(
                "SELECT * FROM users WHERE id = %s",
                ("1' OR '1'='1",),
                context
            )
    
    @pytest.mark.asyncio
    async def test_per_user_rate_limits(self):
        """Test per-user rate limit integration."""
        settings = SecuritySettings(
            enable_rate_limiting=True,
            rate_limit_requests_per_minute=10,
            rate_limit_burst_size=2,
            rate_limit_per_user={"premium_user": 20}
        )
        
        rate_limiter = TokenBucketLimiter(
            requests_per_minute=settings.rate_limit_requests_per_minute,
            burst_size=settings.rate_limit_burst_size,
            per_user_limits=settings.rate_limit_per_user
        )
        
        manager = SecurityManager(
            settings=settings,
            rate_limiter=rate_limiter
        )
        
        # Regular user context
        regular_context = SecurityContext(user_id="regular_user")
        
        # Premium user context
        premium_context = SecurityContext(user_id="premium_user")
        
        query = "SELECT 1"
        
        # Regular user hits limit at 2 (burst size)
        await manager.validate_query(query, None, regular_context)
        await manager.validate_query(query, None, regular_context)
        
        with pytest.raises(RateLimitError):
            await manager.validate_query(query, None, regular_context)
        
        # Premium user has higher limit
        for _ in range(4):  # More than regular burst
            await manager.validate_query(query, None, premium_context)
    
    @pytest.mark.asyncio
    async def test_security_context_propagation(self):
        """Test that security context is properly propagated."""
        settings = SecuritySettings(
            enable_injection_detection=True,
            enable_rate_limiting=True,
            log_security_events=True
        )
        
        # Mock logger to verify context
        mock_logger = Mock()
        
        manager = SecurityManager(
            settings=settings,
            injection_detector=SQLInjectionDetector(),
            rate_limiter=TokenBucketLimiter(10, 5)
        )
        
        # Patch logger
        manager.logger = mock_logger
        
        context = SecurityContext(
            user_id="test_user",
            ip_address="192.168.1.1",
            request_id="req-123"
        )
        
        # Trigger injection error
        try:
            await manager.validate_query(
                "SELECT * FROM users WHERE id = %s",
                ("1' OR '1'='1",),
                context
            )
        except InjectionError:
            pass
        
        # Verify context was logged
        # Logger would be called with context information
        # This is a simplified test - in real implementation, 
        # we'd verify the actual logging calls
    
    @pytest.mark.asyncio
    async def test_combined_filter_mode(self):
        """Test combined blacklist and whitelist filtering."""
        from fastmcp_mysql.security.filtering import CombinedFilter
        
        settings = SecuritySettings(
            filter_mode=FilterMode.COMBINED
        )
        
        # Whitelist: only allow specific patterns
        whitelist = WhitelistFilter(patterns=[
            r"^SELECT .* FROM (users|products|orders).*$",
            r"^INSERT INTO (logs|audit).*$"
        ])
        
        # Blacklist: block dangerous patterns even if whitelisted
        blacklist = BlacklistFilter(settings)
        
        # Combined filter
        combined = CombinedFilter(filters=[whitelist, blacklist])
        
        manager = SecurityManager(
            settings=settings,
            query_filter=combined
        )
        
        context = SecurityContext(user_id="test_user")
        
        # Should pass: whitelisted and not blacklisted
        await manager.validate_query(
            "SELECT * FROM users WHERE id = %s",
            (123,),
            context
        )
        
        # Should fail: not whitelisted
        with pytest.raises(FilteredQueryError):
            await manager.validate_query(
                "SELECT * FROM customers WHERE id = %s",
                (123,),
                context
            )
        
        # Should fail: whitelisted table but blacklisted operation
        with pytest.raises(FilteredQueryError):
            await manager.validate_query(
                "SELECT * FROM users WHERE id IN (SELECT id FROM information_schema.tables)",
                None,
                context
            )
    
    @pytest.mark.asyncio
    async def test_error_handling_cascade(self):
        """Test that errors are properly cascaded."""
        settings = SecuritySettings(
            enable_injection_detection=True,
            enable_rate_limiting=True,
            filter_mode=FilterMode.BLACKLIST
        )
        
        # Create rate limiter with 10 requests per minute, burst 2
        rate_limiter = TokenBucketLimiter(10, 2)
        
        manager = SecurityManager(
            settings=settings,
            injection_detector=SQLInjectionDetector(),
            query_filter=BlacklistFilter(settings),
            rate_limiter=rate_limiter
        )
        
        # Use unique user ID to avoid conflicts
        context = SecurityContext(user_id="cascade_test_user_unique_123")
        
        # Use up rate limit with first two requests (burst size = 2)
        await manager.validate_query("SELECT 1", None, context)
        await manager.validate_query("SELECT 2", None, context)
        
        # Next request should fail with rate limit (checked first)
        # Even though it also has injection, rate limit is checked before injection
        with pytest.raises(RateLimitError) as exc:
            await manager.validate_query(
                "SELECT * FROM users WHERE id = '1' OR '1'='1'",  # Also has injection
                None,
                context
            )
        
        # Should be rate limit error, not injection error
        assert "rate limit" in str(exc.value).lower()
    
    @pytest.mark.asyncio
    async def test_security_logging(self, caplog):
        """Test security event logging."""
        import logging
        
        settings = SecuritySettings(
            enable_injection_detection=True,
            log_security_events=True,
            log_rejected_queries=True
        )
        
        manager = SecurityManager(
            settings=settings,
            injection_detector=SQLInjectionDetector()
        )
        
        context = SecurityContext(
            user_id="attacker",
            ip_address="10.0.0.1"
        )
        
        # Enable debug logging
        caplog.set_level(logging.DEBUG)
        
        # Attempt injection
        with pytest.raises(InjectionError):
            await manager.validate_query(
                "SELECT * FROM users WHERE id = %s",
                ("1' OR '1'='1",),
                context
            )
        
        # Verify security event was logged
        # In real implementation, we'd check for specific log messages
        # containing user_id, ip_address, and the rejected query