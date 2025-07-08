"""Query filter interface for clean architecture."""

from abc import ABC, abstractmethod
from typing import Optional, Tuple


class QueryFilter(ABC):
    """Abstract base class for query filters."""
    
    @abstractmethod
    async def filter(self, query: str, params: Optional[tuple] = None) -> Tuple[bool, Optional[str]]:
        """
        Filter a query based on security rules.
        
        Args:
            query: SQL query to filter
            params: Query parameters
            
        Returns:
            Tuple of (is_allowed, rejection_reason)
            If allowed, rejection_reason is None
        """
        pass