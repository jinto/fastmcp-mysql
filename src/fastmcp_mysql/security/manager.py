"""Security manager for coordinating all security features."""

import logging
from typing import List, Optional
from dataclasses import dataclass

from .interfaces import QueryFilter, RateLimiter, InjectionDetector
from .config import SecuritySettings
from .exceptions import SecurityError, InjectionError, FilterError, RateLimitError, FilteredQueryError


logger = logging.getLogger(__name__)


@dataclass
class SecurityContext:
    """Security context containing request information."""
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    
    @property
    def identifier(self) -> str:
        """Get a unique identifier for rate limiting."""
        return self.user_id or self.ip_address or self.session_id or "anonymous"


class SecurityManager:
    """Manages all security features."""
    
    def __init__(
        self,
        settings: SecuritySettings,
        query_filter: Optional[QueryFilter] = None,
        rate_limiter: Optional[RateLimiter] = None,
        injection_detector: Optional[InjectionDetector] = None
    ):
        """
        Initialize security manager.
        
        Args:
            settings: Security configuration
            query_filter: Query filter implementation
            rate_limiter: Rate limiter implementation
            injection_detector: SQL injection detector
        """
        self.settings = settings
        self.query_filter = query_filter
        self.rate_limiter = rate_limiter
        self.injection_detector = injection_detector
        self.logger = logger
    
    async def validate_query(
        self,
        query: str,
        params: Optional[tuple] = None,
        context: Optional[SecurityContext] = None
    ) -> None:
        """
        Validate a query against all security rules.
        
        Args:
            query: SQL query to validate
            params: Query parameters
            context: Security context
            
        Raises:
            SecurityError: If validation fails
        """
        context = context or SecurityContext()
        
        # 1. Check query length
        if len(query) > self.settings.max_query_length:
            raise SecurityError(f"Query too long: {len(query)} > {self.settings.max_query_length}")
        
        # 2. Rate limiting
        if self.settings.enable_rate_limiting and self.rate_limiter:
            allowed = await self.rate_limiter.check_limit(context.identifier)
            if not allowed:
                raise RateLimitError(
                    f"Rate limit exceeded for user: {context.identifier}"
                )
        
        # 3. SQL injection detection
        if self.settings.enable_injection_detection and self.injection_detector:
            threats = self.injection_detector.detect(query, params)
            if threats:
                self._log_security_event("injection_detected", {
                    "query": query[:200],  # Truncate for logging
                    "threats": threats,
                    "user": context.identifier
                })
                raise InjectionError(
                    f"Potential SQL injection detected: {', '.join(threats)}"
                )
            
            # Also validate parameters
            if params:
                param_threats = self.injection_detector.validate_parameters(params)
                if param_threats:
                    self._log_security_event("injection_in_params", {
                        "threats": param_threats,
                        "user": context.identifier
                    })
                    raise InjectionError(
                        f"Suspicious parameters detected: {', '.join(param_threats)}"
                    )
        
        # 4. Query filtering
        if self.query_filter:
            try:
                self.query_filter.validate(query)
            except FilteredQueryError as e:
                self._log_security_event("query_filtered", {
                    "query": query[:200],
                    "reason": str(e),
                    "filter": self.query_filter.__class__.__name__,
                    "user": context.identifier
                })
                raise
        
        # 6. Audit logging
        if self.settings.audit_all_queries:
            self._log_security_event("query_executed", {
                "query": query[:200],
                "user": context.identifier
            })
    
    def _log_security_event(self, event_type: str, details: dict) -> None:
        """Log a security event."""
        if not self.settings.log_security_events:
            return
        
        logger.warning(
            f"Security event: {event_type}",
            extra={
                "event_type": event_type,
                "details": details
            }
        )