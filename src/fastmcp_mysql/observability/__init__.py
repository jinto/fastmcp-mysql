"""Observability module for FastMCP MySQL server."""

from .health import ComponentHealth, HealthChecker, HealthCheckResult, HealthStatus
from .logging import (
    ContextLogger,
    EnhancedJSONFormatter,
    MetricsLogger,
    RequestContext,
    request_context,
    setup_enhanced_logging,
)
from .metrics import (
    CacheMetrics,
    ConnectionPoolMetrics,
    ErrorMetrics,
    MetricsCollector,
    QueryMetrics,
)
from .tracing import (
    SpanContext,
    SpanKind,
    TracingManager,
    trace_connection,
    trace_query,
)

__all__ = [
    # Logging
    "EnhancedJSONFormatter",
    "setup_enhanced_logging",
    "ContextLogger",
    "RequestContext",
    "MetricsLogger",
    "request_context",
    # Metrics
    "MetricsCollector",
    "QueryMetrics",
    "ConnectionPoolMetrics",
    "CacheMetrics",
    "ErrorMetrics",
    # Health
    "HealthChecker",
    "HealthStatus",
    "ComponentHealth",
    "HealthCheckResult",
    # Tracing
    "TracingManager",
    "SpanContext",
    "SpanKind",
    "trace_query",
    "trace_connection",
]
