"""Whitelist-based query filter."""

import re
from typing import List, Pattern

from ..interfaces import QueryFilter
from ..exceptions import FilteredQueryError


class WhitelistFilter(QueryFilter):
    """Filter queries based on whitelist patterns."""
    
    def __init__(self, patterns: List[str]):
        """
        Initialize whitelist filter.
        
        Args:
            patterns: List of regex patterns for allowed queries
        """
        self.patterns: List[Pattern] = []
        
        # Compile patterns
        for pattern in patterns:
            self.patterns.append(re.compile(pattern, re.IGNORECASE))
    
    def is_allowed(self, query: str) -> bool:
        """
        Check if query matches whitelist.
        
        Args:
            query: SQL query to check
            
        Returns:
            True if query matches whitelist, False otherwise
        """
        for pattern in self.patterns:
            if pattern.match(query):
                return True
        return False
    
    def validate(self, query: str) -> None:
        """
        Validate query against whitelist.
        
        Args:
            query: SQL query to validate
            
        Raises:
            FilteredQueryError: If query doesn't match whitelist
        """
        if not self.is_allowed(query):
            raise FilteredQueryError(
                f"Query not whitelisted. Query must match one of the allowed patterns."
            )