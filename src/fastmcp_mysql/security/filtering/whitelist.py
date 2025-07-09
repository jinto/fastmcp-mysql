"""Whitelist-based query filter."""

import re
from re import Pattern

from ..exceptions import FilteredQueryError
from ..interfaces import QueryFilter


class WhitelistFilter(QueryFilter):
    """Filter queries based on whitelist patterns."""

    def __init__(self, patterns: list[str]):
        """
        Initialize whitelist filter.

        Args:
            patterns: List of regex patterns for allowed queries
        """
        self.patterns: list[Pattern] = []

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
        return any(pattern.match(query) for pattern in self.patterns)

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
                "Query not whitelisted. Query must match one of the allowed patterns."
            )
