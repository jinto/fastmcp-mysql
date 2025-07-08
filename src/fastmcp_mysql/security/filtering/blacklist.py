"""Blacklist-based query filter."""

import re
from typing import List, Pattern

from ..interfaces import QueryFilter
from ..exceptions import FilteredQueryError
from ..config import SecuritySettings


class BlacklistFilter(QueryFilter):
    """Filter queries based on blacklist patterns."""
    
    def __init__(self, settings: SecuritySettings = None, additional_patterns: List[str] = None):
        """
        Initialize blacklist filter.
        
        Args:
            settings: Security settings (optional)
            additional_patterns: Additional patterns to blacklist
        """
        self.settings = settings or SecuritySettings()
        self.patterns: List[Pattern] = []
        
        # Compile default patterns
        for pattern in self.settings.blacklist_patterns:
            self.patterns.append(re.compile(pattern, re.IGNORECASE))
        
        # Add additional patterns if provided
        if additional_patterns:
            for pattern in additional_patterns:
                self.patterns.append(re.compile(pattern, re.IGNORECASE))
    
    def is_allowed(self, query: str) -> bool:
        """
        Check if query passes blacklist.
        
        Args:
            query: SQL query to check
            
        Returns:
            False if query matches blacklist, True otherwise
        """
        for pattern in self.patterns:
            if pattern.search(query):
                return False
        return True
    
    def validate(self, query: str) -> None:
        """
        Validate query against blacklist.
        
        Args:
            query: SQL query to validate
            
        Raises:
            FilteredQueryError: If query matches blacklist
        """
        for pattern in self.patterns:
            match = pattern.search(query)
            if match:
                # Extract the matched portion for better error message
                matched_text = match.group(0)
                raise FilteredQueryError(
                    f"Query contains blacklisted pattern: '{matched_text}'"
                )