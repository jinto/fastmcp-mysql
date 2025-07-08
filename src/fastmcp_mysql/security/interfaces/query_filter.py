"""Query filter interface for clean architecture."""

from abc import ABC, abstractmethod
from typing import Optional


class QueryFilter(ABC):
    """Abstract base class for query filters."""
    
    @abstractmethod
    def is_allowed(self, query: str) -> bool:
        """
        Check if a query is allowed.
        
        Args:
            query: SQL query to check
            
        Returns:
            True if allowed, False otherwise
        """
        pass
    
    @abstractmethod
    def validate(self, query: str) -> None:
        """
        Validate a query and raise exception if not allowed.
        
        Args:
            query: SQL query to validate
            
        Raises:
            FilteredQueryError: If query is not allowed
        """
        pass