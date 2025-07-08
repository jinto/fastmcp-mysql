"""Integration tests for security features with query execution."""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from typing import Dict, Any

from fastmcp_mysql.tools.query import (
    mysql_query, QueryExecutor, QueryValidator,
    set_connection_manager, set_security_manager
)
from fastmcp_mysql.connection import ConnectionManager
from fastmcp_mysql.security import SecurityManager, SecurityContext, SecuritySettings
from fastmcp_mysql.security.injection import SQLInjectionDetector
from fastmcp_mysql.security.filtering import BlacklistFilter
from fastmcp_mysql.security.rate_limiting import TokenBucketLimiter
from fastmcp_mysql.security.exceptions import InjectionError, FilteredQueryError, RateLimitError


@pytest.fixture
async def mock_connection_manager():
    """Create a mock connection manager."""
    manager = Mock(spec=ConnectionManager)
    manager.execute = AsyncMock(return_value=[{"id": 1, "name": "test"}])
    return manager


@pytest.fixture
def security_manager():
    """Create a security manager with all features enabled."""
    settings = SecuritySettings(
        enable_injection_detection=True,
        enable_rate_limiting=True,
        rate_limit_requests_per_minute=10,
        rate_limit_burst_size=2
    )
    
    return SecurityManager(
        settings=settings,
        injection_detector=SQLInjectionDetector(),
        query_filter=BlacklistFilter(settings),
        rate_limiter=TokenBucketLimiter(10, 2)
    )


class TestSecurityIntegration:
    """Test security integration with query execution."""
    
    @pytest.mark.asyncio
    async def test_safe_query_execution(self, mock_connection_manager, security_manager):
        """Test that safe queries execute successfully."""
        # Set up managers
        set_connection_manager(mock_connection_manager)
        set_security_manager(security_manager)
        
        # Execute safe query
        result = await mysql_query(
            query="SELECT * FROM users WHERE id = %s",
            params=[123]
        )
        
        assert result["success"] is True
        assert result["data"] == [{"id": 1, "name": "test"}]
        assert mock_connection_manager.execute.called
    
    @pytest.mark.asyncio
    async def test_sql_injection_blocked(self, mock_connection_manager, security_manager):
        """Test that SQL injection attempts are blocked."""
        # Set up managers
        set_connection_manager(mock_connection_manager)
        set_security_manager(security_manager)
        
        # Attempt SQL injection
        result = await mysql_query(
            query="SELECT * FROM users WHERE id = %s",
            params=["1' OR '1'='1"]
        )
        
        assert result["success"] is False
        assert "injection" in result["error"].lower()
        assert not mock_connection_manager.execute.called
    
    @pytest.mark.asyncio
    async def test_blacklisted_query_blocked(self, mock_connection_manager, security_manager):
        """Test that blacklisted queries are blocked."""
        # Set up managers
        set_connection_manager(mock_connection_manager)
        set_security_manager(security_manager)
        
        # Attempt blacklisted query
        result = await mysql_query(
            query="SELECT * FROM information_schema.tables"
        )
        
        assert result["success"] is False
        assert "blacklisted" in result["error"].lower()
        assert not mock_connection_manager.execute.called
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, mock_connection_manager, security_manager):
        """Test that rate limiting works."""
        # Set up managers
        set_connection_manager(mock_connection_manager)
        set_security_manager(security_manager)
        
        # Reset rate limiter for clean test
        await security_manager.rate_limiter.reset("anonymous")
        
        # Execute queries up to burst limit
        for i in range(2):  # burst_size = 2
            result = await mysql_query(query="SELECT 1")
            assert result["success"] is True
        
        # Next query should be rate limited
        result = await mysql_query(query="SELECT 1")
        assert result["success"] is False
        assert "rate limit" in result["error"].lower()
    
    @pytest.mark.asyncio
    async def test_security_disabled(self, mock_connection_manager):
        """Test that queries work when security is disabled."""
        # Set up only connection manager (no security)
        set_connection_manager(mock_connection_manager)
        set_security_manager(None)
        
        # Even "dangerous" queries should work
        result = await mysql_query(
            query="SELECT * FROM users WHERE id = '1' OR '1'='1'"
        )
        
        assert result["success"] is True
        assert mock_connection_manager.execute.called
    
    @pytest.mark.asyncio
    async def test_context_propagation(self, mock_connection_manager):
        """Test that FastMCP context is properly propagated to security."""
        # Create a fresh security manager for this test
        settings = SecuritySettings(
            enable_injection_detection=True,
            enable_rate_limiting=True,
            rate_limit_requests_per_minute=10,
            rate_limit_burst_size=3  # Slightly higher for this test
        )
        
        security_manager = SecurityManager(
            settings=settings,
            injection_detector=SQLInjectionDetector(),
            query_filter=BlacklistFilter(settings),
            rate_limiter=TokenBucketLimiter(10, 3)
        )
        
        # Set up managers
        set_connection_manager(mock_connection_manager)
        set_security_manager(security_manager)
        
        # Create mock FastMCP context
        mock_context = Mock()
        mock_context.user_id = "test_user_unique_456"
        mock_context.ip_address = "192.168.1.1"
        mock_context.session_id = "session_456"
        
        # Execute queries with context
        # This user should have their own limit
        for i in range(3):  # burst_size = 3
            result = await mysql_query(
                query="SELECT 1",
                context=mock_context
            )
            assert result["success"] is True
        
        # Should hit rate limit for this user
        result = await mysql_query(
            query="SELECT 1",
            context=mock_context
        )
        assert result["success"] is False
        assert "rate limit" in result["error"].lower()
    
    @pytest.mark.asyncio
    async def test_query_validator_still_works(self, mock_connection_manager):
        """Test that the original query validator still blocks DDL."""
        # Set up managers without security to test QueryValidator
        set_connection_manager(mock_connection_manager)
        set_security_manager(None)  # Disable security to test QueryValidator
        
        # DDL should be blocked by QueryValidator
        result = await mysql_query(
            query="DROP TABLE users"
        )
        
        assert result["success"] is False
        assert "DDL operations are not allowed" in result["error"]
        assert not mock_connection_manager.execute.called
    
    @pytest.mark.asyncio
    async def test_error_precedence(self, mock_connection_manager, security_manager):
        """Test that security errors take precedence over query validation."""
        # Set up managers
        set_connection_manager(mock_connection_manager)
        set_security_manager(security_manager)
        
        # Query that would fail both security and validation
        # (injection + DDL)
        result = await mysql_query(
            query="DROP TABLE users WHERE '1'='1'"
        )
        
        # Security should catch it first
        assert result["success"] is False
        # Could be either injection or blacklist, but not DDL
        assert "DDL operations are not allowed" not in result["error"]