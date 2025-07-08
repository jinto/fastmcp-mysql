"""SQL injection detector interface for clean architecture."""

from abc import ABC, abstractmethod
from typing import List, Optional


class InjectionDetector(ABC):
    """Abstract base class for SQL injection detectors."""
    
    @abstractmethod
    def detect(self, query: str, params: Optional[tuple] = None) -> List[str]:
        """
        Detect potential SQL injection patterns.
        
        Args:
            query: SQL query to analyze
            params: Query parameters
            
        Returns:
            List of detected threats/patterns. Empty list if safe.
        """
        pass
    
    @abstractmethod
    def validate_parameters(self, params: tuple) -> List[str]:
        """
        Validate query parameters for injection attempts.
        
        Args:
            params: Query parameters to validate
            
        Returns:
            List of detected threats. Empty list if safe.
        """
        pass