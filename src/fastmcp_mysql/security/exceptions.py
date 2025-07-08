"""Security-related exceptions."""


class SecurityError(Exception):
    """Base exception for security-related errors."""
    pass


class InjectionError(SecurityError):
    """Raised when SQL injection is detected."""
    pass


class FilterError(SecurityError):
    """Raised when a query is rejected by filters."""
    pass


class FilteredQueryError(FilterError):
    """Raised when a query is rejected by filters."""
    pass


class RateLimitError(SecurityError):
    """Raised when rate limit is exceeded."""
    pass