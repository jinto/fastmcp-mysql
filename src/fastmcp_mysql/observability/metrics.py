"""Metrics collection system for FastMCP MySQL server."""

import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Deque, Callable
from enum import Enum


class MetricType(Enum):
    """Types of metrics."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


@dataclass
class Metric:
    """Base metric class."""
    name: str
    type: MetricType
    description: str
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class QueryMetrics:
    """Metrics for query execution."""
    total_queries: int = 0
    successful_queries: int = 0
    failed_queries: int = 0
    query_duration_ms: List[float] = field(default_factory=list)
    queries_by_type: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    slow_queries: List[Dict[str, Any]] = field(default_factory=list)
    
    def record_query(self, query_type: str, duration_ms: float, success: bool,
                    query: str, threshold_ms: float = 1000):
        """Record query execution metrics."""
        self.total_queries += 1
        self.queries_by_type[query_type] += 1
        self.query_duration_ms.append(duration_ms)
        
        if success:
            self.successful_queries += 1
        else:
            self.failed_queries += 1
        
        # Track slow queries
        if duration_ms > threshold_ms:
            self.slow_queries.append({
                "query": query[:200],  # Truncate long queries
                "duration_ms": duration_ms,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": query_type,
            })
            # Keep only last 100 slow queries
            if len(self.slow_queries) > 100:
                self.slow_queries = self.slow_queries[-100:]
    
    def get_percentiles(self) -> Dict[str, float]:
        """Calculate query duration percentiles."""
        if not self.query_duration_ms:
            return {"p50": 0, "p90": 0, "p95": 0, "p99": 0}
        
        sorted_durations = sorted(self.query_duration_ms)
        n = len(sorted_durations)
        
        return {
            "p50": sorted_durations[int(n * 0.5)],
            "p90": sorted_durations[int(n * 0.9)],
            "p95": sorted_durations[int(n * 0.95)],
            "p99": sorted_durations[int(n * 0.99)],
        }
    
    def get_error_rate(self) -> float:
        """Calculate query error rate."""
        if self.total_queries == 0:
            return 0.0
        return (self.failed_queries / self.total_queries) * 100


@dataclass
class ConnectionPoolMetrics:
    """Metrics for connection pool."""
    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    wait_time_ms: List[float] = field(default_factory=list)
    connection_errors: int = 0
    max_connections: int = 0
    
    def update(self, total: int, active: int, max_size: int):
        """Update connection pool metrics."""
        self.total_connections = total
        self.active_connections = active
        self.idle_connections = total - active
        self.max_connections = max_size
    
    def record_wait_time(self, wait_ms: float):
        """Record connection wait time."""
        self.wait_time_ms.append(wait_ms)
        # Keep only last 1000 measurements
        if len(self.wait_time_ms) > 1000:
            self.wait_time_ms = self.wait_time_ms[-1000:]
    
    def record_connection_error(self):
        """Record connection error."""
        self.connection_errors += 1
    
    def get_utilization(self) -> float:
        """Calculate connection pool utilization."""
        if self.max_connections == 0:
            return 0.0
        return (self.active_connections / self.max_connections) * 100
    
    def get_avg_wait_time(self) -> float:
        """Calculate average connection wait time."""
        if not self.wait_time_ms:
            return 0.0
        return sum(self.wait_time_ms) / len(self.wait_time_ms)


@dataclass
class CacheMetrics:
    """Metrics for cache performance."""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    current_size: int = 0
    max_size: int = 0
    
    def record_hit(self):
        """Record cache hit."""
        self.hits += 1
    
    def record_miss(self):
        """Record cache miss."""
        self.misses += 1
    
    def record_eviction(self):
        """Record cache eviction."""
        self.evictions += 1
    
    def update_size(self, current: int, max_size: int):
        """Update cache size metrics."""
        self.current_size = current
        self.max_size = max_size
    
    def get_hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self.hits + self.misses
        if total == 0:
            return 0.0
        return (self.hits / total) * 100
    
    def get_utilization(self) -> float:
        """Calculate cache utilization."""
        if self.max_size == 0:
            return 0.0
        return (self.current_size / self.max_size) * 100


@dataclass 
class ErrorMetrics:
    """Metrics for error tracking."""
    errors_by_type: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    error_timeline: Deque[Dict[str, Any]] = field(default_factory=lambda: deque(maxlen=1000))
    
    def record_error(self, error_type: str, error_msg: str, context: Optional[Dict[str, Any]] = None):
        """Record an error occurrence."""
        self.errors_by_type[error_type] += 1
        
        error_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": error_type,
            "message": error_msg[:500],  # Truncate long messages
            "context": context or {},
        }
        self.error_timeline.append(error_entry)
    
    def get_error_rate(self, window_seconds: int = 60) -> Dict[str, float]:
        """Calculate error rate per type over time window."""
        current_time = time.time()
        window_start = current_time - window_seconds
        
        # Count errors in window
        window_errors = defaultdict(int)
        for error in self.error_timeline:
            # Parse timestamp
            error_time = datetime.fromisoformat(error["timestamp"].replace('Z', '+00:00'))
            error_timestamp = error_time.timestamp()
            
            if error_timestamp >= window_start:
                window_errors[error["type"]] += 1
        
        # Calculate rate per minute
        return {
            error_type: (count / window_seconds) * 60
            for error_type, count in window_errors.items()
        }


class MetricsCollector:
    """Central metrics collector for the application."""
    
    def __init__(self):
        """Initialize metrics collector."""
        self.query_metrics = QueryMetrics()
        self.connection_metrics = ConnectionPoolMetrics()
        self.cache_metrics = CacheMetrics()
        self.error_metrics = ErrorMetrics()
        self._lock = threading.Lock()
        self._custom_metrics: Dict[str, Any] = {}
        self._metric_callbacks: List[Callable[[Dict[str, Any]], None]] = []
    
    def record_query(self, query_type: str, duration_ms: float, success: bool,
                    query: str, threshold_ms: float = 1000):
        """Thread-safe query metrics recording."""
        with self._lock:
            self.query_metrics.record_query(query_type, duration_ms, success, query, threshold_ms)
    
    def update_connection_pool(self, total: int, active: int, max_size: int):
        """Thread-safe connection pool metrics update."""
        with self._lock:
            self.connection_metrics.update(total, active, max_size)
    
    def record_cache_hit(self):
        """Thread-safe cache hit recording."""
        with self._lock:
            self.cache_metrics.record_hit()
    
    def record_cache_miss(self):
        """Thread-safe cache miss recording."""
        with self._lock:
            self.cache_metrics.record_miss()
    
    def record_error(self, error_type: str, error_msg: str, context: Optional[Dict[str, Any]] = None):
        """Thread-safe error recording."""
        with self._lock:
            self.error_metrics.record_error(error_type, error_msg, context)
    
    def register_custom_metric(self, name: str, value: Any):
        """Register a custom metric."""
        with self._lock:
            self._custom_metrics[name] = value
    
    def register_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """Register a callback for metrics export."""
        self._metric_callbacks.append(callback)
    
    def export_metrics(self) -> Dict[str, Any]:
        """Export all metrics as a dictionary."""
        with self._lock:
            percentiles = self.query_metrics.get_percentiles()
            error_rates = self.error_metrics.get_error_rate()
            
            metrics = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "query": {
                    "total": self.query_metrics.total_queries,
                    "successful": self.query_metrics.successful_queries,
                    "failed": self.query_metrics.failed_queries,
                    "error_rate": self.query_metrics.get_error_rate(),
                    "by_type": dict(self.query_metrics.queries_by_type),
                    "duration_percentiles_ms": percentiles,
                    "slow_queries_count": len(self.query_metrics.slow_queries),
                },
                "connection_pool": {
                    "total": self.connection_metrics.total_connections,
                    "active": self.connection_metrics.active_connections,
                    "idle": self.connection_metrics.idle_connections,
                    "utilization_percent": self.connection_metrics.get_utilization(),
                    "avg_wait_time_ms": self.connection_metrics.get_avg_wait_time(),
                    "errors": self.connection_metrics.connection_errors,
                },
                "cache": {
                    "hits": self.cache_metrics.hits,
                    "misses": self.cache_metrics.misses,
                    "hit_rate_percent": self.cache_metrics.get_hit_rate(),
                    "evictions": self.cache_metrics.evictions,
                    "size": self.cache_metrics.current_size,
                    "utilization_percent": self.cache_metrics.get_utilization(),
                },
                "errors": {
                    "by_type": dict(self.error_metrics.errors_by_type),
                    "rate_per_minute": error_rates,
                    "recent_errors": list(self.error_metrics.error_timeline)[-10:],  # Last 10 errors
                },
                "custom": self._custom_metrics.copy(),
            }
            
            # Call registered callbacks
            for callback in self._metric_callbacks:
                try:
                    callback(metrics)
                except Exception:
                    pass  # Ignore callback errors
            
            return metrics
    
    def export_prometheus(self) -> str:
        """Export metrics in Prometheus format."""
        lines = []
        metrics = self.export_metrics()
        
        # Query metrics
        lines.append(f'# HELP mysql_queries_total Total number of queries')
        lines.append(f'# TYPE mysql_queries_total counter')
        lines.append(f'mysql_queries_total {metrics["query"]["total"]}')
        
        lines.append(f'# HELP mysql_queries_successful Successful queries')
        lines.append(f'# TYPE mysql_queries_successful counter')
        lines.append(f'mysql_queries_successful {metrics["query"]["successful"]}')
        
        lines.append(f'# HELP mysql_queries_failed Failed queries')
        lines.append(f'# TYPE mysql_queries_failed counter')
        lines.append(f'mysql_queries_failed {metrics["query"]["failed"]}')
        
        # Query duration percentiles
        for percentile, value in metrics["query"]["duration_percentiles_ms"].items():
            lines.append(f'# HELP mysql_query_duration_ms Query duration in milliseconds')
            lines.append(f'# TYPE mysql_query_duration_ms summary')
            lines.append(f'mysql_query_duration_ms{{quantile="{percentile[1:]}"}} {value}')
        
        # Connection pool metrics
        lines.append(f'# HELP mysql_connections_active Active connections')
        lines.append(f'# TYPE mysql_connections_active gauge')
        lines.append(f'mysql_connections_active {metrics["connection_pool"]["active"]}')
        
        lines.append(f'# HELP mysql_connections_idle Idle connections')
        lines.append(f'# TYPE mysql_connections_idle gauge')
        lines.append(f'mysql_connections_idle {metrics["connection_pool"]["idle"]}')
        
        lines.append(f'# HELP mysql_connection_pool_utilization Connection pool utilization percentage')
        lines.append(f'# TYPE mysql_connection_pool_utilization gauge')
        lines.append(f'mysql_connection_pool_utilization {metrics["connection_pool"]["utilization_percent"]}')
        
        # Cache metrics
        lines.append(f'# HELP mysql_cache_hits Cache hits')
        lines.append(f'# TYPE mysql_cache_hits counter')
        lines.append(f'mysql_cache_hits {metrics["cache"]["hits"]}')
        
        lines.append(f'# HELP mysql_cache_misses Cache misses')
        lines.append(f'# TYPE mysql_cache_misses counter')
        lines.append(f'mysql_cache_misses {metrics["cache"]["misses"]}')
        
        lines.append(f'# HELP mysql_cache_hit_rate Cache hit rate percentage')
        lines.append(f'# TYPE mysql_cache_hit_rate gauge')
        lines.append(f'mysql_cache_hit_rate {metrics["cache"]["hit_rate_percent"]}')
        
        # Error metrics
        for error_type, count in metrics["errors"]["by_type"].items():
            lines.append(f'# HELP mysql_errors_total Total errors by type')
            lines.append(f'# TYPE mysql_errors_total counter')
            lines.append(f'mysql_errors_total{{type="{error_type}"}} {count}')
        
        return '\n'.join(lines)


# Global metrics collector instance
_metrics_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """Get or create the global metrics collector."""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector