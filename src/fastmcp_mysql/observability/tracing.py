"""Distributed tracing support for FastMCP MySQL server."""

import time
import uuid
import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, AsyncIterator
from enum import Enum

try:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.trace import Status, StatusCode
    OPENTELEMETRY_AVAILABLE = True
except ImportError:
    OPENTELEMETRY_AVAILABLE = False
    trace = None


class SpanKind(Enum):
    """Types of spans."""
    INTERNAL = "internal"
    SERVER = "server"
    CLIENT = "client"
    PRODUCER = "producer"
    CONSUMER = "consumer"


@dataclass
class SpanContext:
    """Context for a tracing span."""
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    span_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    parent_span_id: Optional[str] = None
    operation_name: str = "unknown"
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "ok"
    kind: SpanKind = SpanKind.INTERNAL
    
    def add_event(self, name: str, attributes: Optional[Dict[str, Any]] = None):
        """Add an event to the span."""
        self.events.append({
            "timestamp": time.time(),
            "name": name,
            "attributes": attributes or {},
        })
    
    def set_attribute(self, key: str, value: Any):
        """Set a span attribute."""
        self.attributes[key] = value
    
    def set_status(self, status: str, message: Optional[str] = None):
        """Set span status."""
        self.status = status
        if message:
            self.attributes["status_message"] = message
    
    def end(self):
        """End the span."""
        self.end_time = time.time()
    
    def duration_ms(self) -> float:
        """Get span duration in milliseconds."""
        if self.end_time:
            return (self.end_time - self.start_time) * 1000
        return 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "operation_name": self.operation_name,
            "start_time": datetime.fromtimestamp(self.start_time, timezone.utc).isoformat(),
            "end_time": datetime.fromtimestamp(self.end_time, timezone.utc).isoformat() if self.end_time else None,
            "duration_ms": self.duration_ms(),
            "attributes": self.attributes,
            "events": self.events,
            "status": self.status,
            "kind": self.kind.value,
        }


class TracingManager:
    """Manager for distributed tracing."""
    
    def __init__(self, service_name: str = "fastmcp-mysql", 
                 otlp_endpoint: Optional[str] = None,
                 enabled: bool = True):
        """Initialize tracing manager.
        
        Args:
            service_name: Service name for traces
            otlp_endpoint: OpenTelemetry collector endpoint
            enabled: Whether tracing is enabled
        """
        self.service_name = service_name
        self.enabled = enabled and OPENTELEMETRY_AVAILABLE
        self.tracer = None
        self._spans: List[SpanContext] = []
        self._current_span: Optional[SpanContext] = None
        
        if self.enabled and otlp_endpoint:
            self._setup_opentelemetry(otlp_endpoint)
    
    def _setup_opentelemetry(self, otlp_endpoint: str):
        """Set up OpenTelemetry tracing."""
        if not OPENTELEMETRY_AVAILABLE:
            return
        
        # Create resource
        resource = Resource.create({
            "service.name": self.service_name,
            "service.version": "1.0.0",
        })
        
        # Create tracer provider
        provider = TracerProvider(resource=resource)
        
        # Create OTLP exporter
        exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
        
        # Add span processor
        provider.add_span_processor(BatchSpanProcessor(exporter))
        
        # Set as global tracer provider
        trace.set_tracer_provider(provider)
        
        # Get tracer
        self.tracer = trace.get_tracer(self.service_name)
    
    @asynccontextmanager
    async def span(self, operation_name: str, kind: SpanKind = SpanKind.INTERNAL,
                   attributes: Optional[Dict[str, Any]] = None) -> AsyncIterator[SpanContext]:
        """Create a new span.
        
        Args:
            operation_name: Name of the operation
            kind: Type of span
            attributes: Initial span attributes
            
        Yields:
            SpanContext for the span
        """
        # Create span context
        parent_span_id = self._current_span.span_id if self._current_span else None
        span_context = SpanContext(
            operation_name=operation_name,
            parent_span_id=parent_span_id,
            kind=kind,
            attributes=attributes or {},
        )
        
        # Set as current span
        old_span = self._current_span
        self._current_span = span_context
        
        # Start OpenTelemetry span if available
        otel_span = None
        if self.tracer:
            otel_span = self.tracer.start_span(
                operation_name,
                kind=getattr(trace.SpanKind, kind.name, trace.SpanKind.INTERNAL)
            )
            if attributes:
                for key, value in attributes.items():
                    otel_span.set_attribute(key, value)
        
        try:
            yield span_context
            span_context.set_status("ok")
        except Exception as e:
            span_context.set_status("error", str(e))
            if otel_span:
                otel_span.set_status(Status(StatusCode.ERROR, str(e)))
            raise
        finally:
            # End span
            span_context.end()
            self._spans.append(span_context)
            
            # Keep only last 1000 spans
            if len(self._spans) > 1000:
                self._spans = self._spans[-1000:]
            
            # End OpenTelemetry span
            if otel_span:
                otel_span.end()
            
            # Restore previous span
            self._current_span = old_span
    
    def get_current_trace_id(self) -> Optional[str]:
        """Get current trace ID."""
        if self._current_span:
            return self._current_span.trace_id
        return None
    
    def get_recent_traces(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent trace spans."""
        return [span.to_dict() for span in self._spans[-limit:]]
    
    def export_traces(self) -> Dict[str, Any]:
        """Export trace data."""
        # Group spans by trace ID
        traces = {}
        for span in self._spans:
            trace_id = span.trace_id
            if trace_id not in traces:
                traces[trace_id] = []
            traces[trace_id].append(span.to_dict())
        
        return {
            "service_name": self.service_name,
            "traces": traces,
            "total_spans": len(self._spans),
        }


# Decorators for common tracing scenarios

def trace_query(func):
    """Decorator to trace query execution."""
    async def wrapper(*args, **kwargs):
        manager = get_tracing_manager()
        if not manager:
            return await func(*args, **kwargs)
        
        # Extract query info
        query = args[0] if args else kwargs.get('query', 'unknown')
        
        async with manager.span("query_execution", SpanKind.CLIENT, {
            "db.statement": query[:200],  # Truncate long queries
            "db.type": "mysql",
        }) as span:
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                span.set_attribute("db.rows_affected", result.get("rows_affected", 0))
                return result
            except Exception as e:
                span.set_attribute("error.type", type(e).__name__)
                raise
            finally:
                duration_ms = (time.time() - start_time) * 1000
                span.set_attribute("duration_ms", duration_ms)
    
    return wrapper


def trace_connection(func):
    """Decorator to trace connection operations."""
    async def wrapper(*args, **kwargs):
        manager = get_tracing_manager()
        if not manager:
            return await func(*args, **kwargs)
        
        async with manager.span("connection_operation", SpanKind.CLIENT, {
            "db.type": "mysql",
            "operation": func.__name__,
        }) as span:
            try:
                result = await func(*args, **kwargs)
                return result
            except Exception as e:
                span.set_attribute("error.type", type(e).__name__)
                raise
    
    return wrapper


# Global tracing manager instance
_tracing_manager: Optional[TracingManager] = None


def setup_tracing(service_name: str = "fastmcp-mysql",
                 otlp_endpoint: Optional[str] = None,
                 enabled: bool = True) -> TracingManager:
    """Set up global tracing manager.
    
    Args:
        service_name: Service name for traces
        otlp_endpoint: OpenTelemetry collector endpoint
        enabled: Whether tracing is enabled
        
    Returns:
        Configured TracingManager
    """
    global _tracing_manager
    _tracing_manager = TracingManager(service_name, otlp_endpoint, enabled)
    return _tracing_manager


def get_tracing_manager() -> Optional[TracingManager]:
    """Get the global tracing manager."""
    return _tracing_manager