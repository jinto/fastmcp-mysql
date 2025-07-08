"""Combined query filter."""

from typing import List

from ..interfaces import QueryFilter
from ..exceptions import FilteredQueryError


class CombinedFilter(QueryFilter):
    """Combine multiple filters with AND logic."""
    
    def __init__(self, filters: List[QueryFilter]):
        """
        Initialize combined filter.
        
        Args:
            filters: List of filters to combine
        """
        self.filters = filters
    
    def is_allowed(self, query: str) -> bool:
        """
        Check if query passes all filters.
        
        Args:
            query: SQL query to check
            
        Returns:
            True if all filters allow the query, False otherwise
        """
        for filter in self.filters:
            if not filter.is_allowed(query):
                return False
        return True
    
    def validate(self, query: str) -> None:
        """
        Validate query against all filters.
        
        Args:
            query: SQL query to validate
            
        Raises:
            FilteredQueryError: If any filter rejects the query
        """
        for filter in self.filters:
            filter.validate(query)  # Will raise if not allowed