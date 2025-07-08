"""Tests for query filtering functionality."""

import pytest
from typing import List

from fastmcp_mysql.security.interfaces import QueryFilter
from fastmcp_mysql.security.config import FilterMode
from fastmcp_mysql.security.exceptions import FilteredQueryError


class TestQueryFiltering:
    """Test query filtering functionality."""
    
    def test_query_filter_interface(self):
        """Test that QueryFilter interface is properly defined."""
        from fastmcp_mysql.security.interfaces import QueryFilter
        
        # Interface should require these methods
        assert hasattr(QueryFilter, 'validate')
        assert hasattr(QueryFilter, 'is_allowed')
    
    @pytest.mark.asyncio
    async def test_blacklist_filter_blocks_dangerous_queries(self, dangerous_queries):
        """Test that blacklist filter blocks dangerous queries."""
        from fastmcp_mysql.security.filtering import BlacklistFilter
        
        filter = BlacklistFilter()
        
        for query in dangerous_queries:
            # Should not be allowed
            assert not filter.is_allowed(query), f"Dangerous query not blocked: {query}"
            
            # Should raise exception on validate
            with pytest.raises(FilteredQueryError) as exc:
                filter.validate(query)
            assert "blacklisted" in str(exc.value).lower()
    
    @pytest.mark.asyncio
    async def test_blacklist_filter_allows_safe_queries(self, safe_queries):
        """Test that blacklist filter allows safe queries."""
        from fastmcp_mysql.security.filtering import BlacklistFilter
        
        filter = BlacklistFilter()
        
        for query in safe_queries:
            # Should be allowed
            assert filter.is_allowed(query), f"Safe query blocked: {query}"
            
            # Should not raise exception
            filter.validate(query)  # Should not raise
    
    def test_whitelist_filter_allows_whitelisted_queries(self):
        """Test that whitelist filter only allows whitelisted queries."""
        from fastmcp_mysql.security.filtering import WhitelistFilter
        
        # Define allowed patterns
        allowed_patterns = [
            r"^SELECT \* FROM users WHERE id = %s$",
            r"^SELECT name, email FROM customers WHERE .+$",
            r"^INSERT INTO logs \(.+\) VALUES \(.+\)$",
        ]
        
        filter = WhitelistFilter(patterns=allowed_patterns)
        
        # These should be allowed
        allowed_queries = [
            "SELECT * FROM users WHERE id = %s",
            "SELECT name, email FROM customers WHERE status = %s",
            "INSERT INTO logs (message, level) VALUES (%s, %s)",
        ]
        
        for query in allowed_queries:
            assert filter.is_allowed(query), f"Whitelisted query blocked: {query}"
            filter.validate(query)  # Should not raise
    
    def test_whitelist_filter_blocks_non_whitelisted_queries(self):
        """Test that whitelist filter blocks non-whitelisted queries."""
        from fastmcp_mysql.security.filtering import WhitelistFilter
        
        # Very restrictive whitelist
        allowed_patterns = [
            r"^SELECT id, name FROM users WHERE id = %s$",
        ]
        
        filter = WhitelistFilter(patterns=allowed_patterns)
        
        # These should be blocked
        blocked_queries = [
            "SELECT * FROM users",  # Not exact match
            "SELECT id, name FROM customers WHERE id = %s",  # Wrong table
            "DELETE FROM users WHERE id = %s",  # Not whitelisted operation
            "SELECT id, name FROM users WHERE id = %s OR 1=1",  # Extra conditions
        ]
        
        for query in blocked_queries:
            assert not filter.is_allowed(query), f"Non-whitelisted query allowed: {query}"
            
            with pytest.raises(FilteredQueryError) as exc:
                filter.validate(query)
            assert "not whitelisted" in str(exc.value).lower()
    
    def test_combined_filter_modes(self):
        """Test combined filter modes (BOTH)."""
        from fastmcp_mysql.security.filtering import CombinedFilter, BlacklistFilter, WhitelistFilter
        
        # Create individual filters
        blacklist = BlacklistFilter()
        whitelist = WhitelistFilter(patterns=[
            r"^SELECT .+ FROM products WHERE .+$",
            r"^INSERT INTO orders .+$",
        ])
        
        # Combined filter (must pass both)
        filter = CombinedFilter(filters=[blacklist, whitelist])
        
        # Should pass both filters
        good_query = "SELECT * FROM products WHERE category = %s"
        assert filter.is_allowed(good_query)
        filter.validate(good_query)  # Should not raise
        
        # Fails whitelist (not in allowed patterns)
        bad_query1 = "SELECT * FROM users WHERE id = %s"
        assert not filter.is_allowed(bad_query1)
        
        # Fails blacklist (information_schema)
        bad_query2 = "SELECT * FROM products WHERE id IN (SELECT id FROM information_schema.tables)"
        assert not filter.is_allowed(bad_query2)
    
    def test_custom_blacklist_patterns(self):
        """Test custom blacklist patterns."""
        from fastmcp_mysql.security.filtering import BlacklistFilter
        
        # Custom patterns to block
        custom_patterns = [
            r"\bTEMP_",  # Block TEMP_ prefix
            r"\bEXPERIMENTAL_",  # Block experimental features
            r"\bpassword\b",  # Block any query mentioning passwords
        ]
        
        filter = BlacklistFilter(additional_patterns=custom_patterns)
        
        blocked_queries = [
            "SELECT * FROM TEMP_users",
            "SELECT EXPERIMENTAL_feature FROM config",
            "SELECT username, password FROM users",
        ]
        
        for query in blocked_queries:
            assert not filter.is_allowed(query), f"Custom pattern not blocked: {query}"
    
    def test_filter_case_sensitivity(self):
        """Test that filters are case-insensitive."""
        from fastmcp_mysql.security.filtering import BlacklistFilter
        
        filter = BlacklistFilter()
        
        # Different case variations of dangerous queries
        variations = [
            "SELECT * FROM INFORMATION_SCHEMA.TABLES",
            "select * from information_schema.tables",
            "SeLeCt * FrOm InFoRmAtIoN_sChEmA.tAbLeS",
        ]
        
        for query in variations:
            assert not filter.is_allowed(query), f"Case variation not blocked: {query}"
    
    def test_filter_with_comments(self):
        """Test that filters detect patterns even with comments."""
        from fastmcp_mysql.security.filtering import BlacklistFilter
        
        filter = BlacklistFilter()
        
        # Queries with comments trying to bypass filters
        commented_queries = [
            "SELECT * FROM /* comment */ information_schema.tables",
            "SELECT * FROM users; -- DROP TABLE users",
            "SELECT LOAD_FILE/* comment */('/etc/passwd')",
        ]
        
        for query in commented_queries:
            assert not filter.is_allowed(query), f"Commented query not blocked: {query}"
    
    @pytest.mark.asyncio
    async def test_filter_performance(self):
        """Test filter performance with many patterns."""
        from fastmcp_mysql.security.filtering import BlacklistFilter
        import time
        
        # Create filter with many patterns
        filter = BlacklistFilter()
        
        # Generate many queries
        queries = [f"SELECT * FROM table{i} WHERE id = %s" for i in range(1000)]
        
        # Measure time
        start = time.time()
        for query in queries:
            filter.is_allowed(query)
        end = time.time()
        
        # Should be fast (less than 200ms for 1000 queries)
        assert (end - start) < 0.2, f"Filter too slow: {end - start}s for 1000 queries"
    
    def test_filter_with_prepared_statements(self):
        """Test that filters allow proper prepared statements."""
        from fastmcp_mysql.security.filtering import BlacklistFilter
        
        filter = BlacklistFilter()
        
        # Prepared statements should be allowed
        prepared_queries = [
            "SELECT * FROM users WHERE id = %s",
            "SELECT * FROM users WHERE id = ? AND status = ?",
            "INSERT INTO logs (message) VALUES (%s)",
            "UPDATE users SET last_login = %s WHERE id = %s",
        ]
        
        for query in prepared_queries:
            assert filter.is_allowed(query), f"Prepared statement blocked: {query}"
    
    def test_filter_error_messages(self):
        """Test that filter errors provide useful information."""
        from fastmcp_mysql.security.filtering import BlacklistFilter, WhitelistFilter
        
        blacklist = BlacklistFilter()
        whitelist = WhitelistFilter(patterns=[r"^SELECT id FROM users$"])
        
        # Blacklist error
        with pytest.raises(FilteredQueryError) as exc:
            blacklist.validate("SELECT * FROM information_schema.tables")
        assert "blacklisted" in str(exc.value).lower()
        assert "information_schema" in str(exc.value).lower()
        
        # Whitelist error
        with pytest.raises(FilteredQueryError) as exc:
            whitelist.validate("DELETE FROM users")
        assert "not whitelisted" in str(exc.value).lower()