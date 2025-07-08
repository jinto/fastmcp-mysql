"""Monitoring and observability system for FastMCP MySQL Server."""
import asyncio
import json
import logging
import time
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

import numpy as np


class HealthStatus(Enum):
    """Health status levels."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class QueryMetrics:
    """Metrics for query performance tracking."""
    
    def __init__(self):
        self.total_queries = 0
        self.successful_queries = 0
        self.failed_queries = 0
        self.query_times: List[float] = []
        self.slow_queries: List[Dict[str, Any]] = []
        self.slow_query_threshold = 1.0  # seconds
        
    def record_query(self, duration: float, success: bool, query: Optional[str] = None):
        """Record query execution metrics."""
        self.total_queries += 1
        self.query_times.append(duration)
        
        if success:
            self.successful_queries += 1
        else:
            self.failed_queries += 1
            
        # Track slow queries
        if duration > self.slow_query_threshold and query:
            self.slow_queries.append({
                "query": query,
                "duration": duration,
                "timestamp": datetime.now()
            })
            # Keep only last 100 slow queries
            if len(self.slow_queries) > 100:
                self.slow_queries = self.slow_queries[-100:]
    
    def get_percentiles(self) -> Dict[str, float]:
        """Calculate query time percentiles."""
        if not self.query_times:
            return {"p50": 0, "p90": 0, "p95": 0, "p99": 0}
            
        times = sorted(self.query_times)
        length = len(times)
        return {
            "p50": float(np.percentile(times, 50)),
            "p90": float(np.percentile(times, 90)),
            "p95": float(np.percentile(times, 95)),
            "p99": float(np.percentile(times, 99))
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get query statistics."""
        success_rate = (
            self.successful_queries / self.total_queries
            if self.total_queries > 0 else 0
        )
        avg_time = (
            sum(self.query_times) / len(self.query_times)
            if self.query_times else 0
        )
        
        return {
            "total_queries": self.total_queries,
            "successful_queries": self.successful_queries,
            "failed_queries": self.failed_queries,
            "success_rate": success_rate,
            "average_time": avg_time,
            "percentiles": self.get_percentiles() if self.query_times else {},
            "slow_queries": len(self.slow_queries)
        }


class ConnectionPoolMetrics:
    """Metrics for connection pool monitoring."""
    
    def __init__(self, max_size: int):
        self.max_size = max_size
        self.active_connections = 0
        self.idle_connections = 0
        self.total_acquired = 0
        self.total_released = 0
        self.wait_times: List[float] = []
        
    def update_pool_state(self, active: int, idle: int):
        """Update current pool state."""
        self.active_connections = active
        self.idle_connections = idle
        
    def record_acquisition(self, wait_time: float):
        """Record connection acquisition."""
        self.total_acquired += 1
        self.wait_times.append(wait_time)
        # Keep only last 1000 wait times
        if len(self.wait_times) > 1000:
            self.wait_times = self.wait_times[-1000:]
            
    def record_release(self):
        """Record connection release."""
        self.total_released += 1
        
    def get_stats(self) -> Dict[str, Any]:
        """Get pool statistics."""
        utilization = (
            (self.active_connections + self.idle_connections) / self.max_size
            if self.max_size > 0 else 0
        )
        avg_wait = (
            sum(self.wait_times) / len(self.wait_times)
            if self.wait_times else 0
        )
        
        return {
            "max_size": self.max_size,
            "active_connections": self.active_connections,
            "idle_connections": self.idle_connections,
            "utilization": utilization,
            "total_acquired": self.total_acquired,
            "total_released": self.total_released,
            "average_wait_time": avg_wait
        }


class CacheMetrics:
    """Metrics for cache performance."""
    
    def __init__(self):
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.size = 0
        
    def record_hit(self):
        """Record cache hit."""
        self.hits += 1
        
    def record_miss(self):
        """Record cache miss."""
        self.misses += 1
        
    def update_size(self, size: int):
        """Update current cache size."""
        self.size = size
        
    def record_eviction(self, count: int = 1):
        """Record cache eviction."""
        self.evictions += count
        
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self.hits + self.misses
        hit_rate = self.hits / total_requests if total_requests > 0 else 0
        
        return {
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": hit_rate,
            "evictions": self.evictions,
            "size": self.size
        }


class ErrorMetrics:
    """Metrics for error tracking."""
    
    def __init__(self):
        self.errors_by_type: Dict[str, int] = defaultdict(int)
        self.error_timeline: List[Dict[str, Any]] = []
        
    def record_error(self, error_type: str, message: str):
        """Record an error occurrence."""
        self.errors_by_type[error_type] += 1
        self.error_timeline.append({
            "timestamp": datetime.now(),
            "type": error_type,
            "message": message
        })
        # Keep only last 1000 errors
        if len(self.error_timeline) > 1000:
            self.error_timeline = self.error_timeline[-1000:]
            
    def get_error_rate(self, window_minutes: int = 60) -> float:
        """Get error rate per hour."""
        cutoff = datetime.now() - timedelta(minutes=window_minutes)
        recent_errors = [
            e for e in self.error_timeline
            if e["timestamp"] > cutoff
        ]
        return len(recent_errors)
        
    def get_stats(self) -> Dict[str, Any]:
        """Get error statistics."""
        return {
            "total_errors": sum(self.errors_by_type.values()),
            "errors_by_type": dict(self.errors_by_type),
            "error_rate_per_hour": self.get_error_rate(),
            "recent_errors": len(self.error_timeline)
        }


class HealthChecker:
    """System health checker."""
    
    def __init__(self):
        self._checks: Dict[str, Callable] = {}
        self._register_default_checks()
        
    def _register_default_checks(self):
        """Register default health checks."""
        self.register_check("database", self.check_database)
        self.register_check("query_performance", self.check_query_performance)
        self.register_check("cache", self.check_cache)
        self.register_check("errors", self.check_errors)
        
    def register_check(self, name: str, check_func: Callable):
        """Register a health check."""
        self._checks[name] = check_func
        
    async def check_database(self, pool_metrics: ConnectionPoolMetrics) -> Dict[str, Any]:
        """Check database connectivity and pool health."""
        stats = pool_metrics.get_stats()
        
        # Handle missing keys
        utilization = stats.get("utilization", 0)
        active = stats.get("active_connections", 0)
        max_size = stats.get("max_size", 10)
        total_acquired = stats.get("total_acquired", 0)
        
        if utilization > 0.9:
            status = HealthStatus.DEGRADED
            message = "Connection pool near capacity"
        elif active == 0 and total_acquired > 0:
            status = HealthStatus.UNHEALTHY
            message = "No active connections"
        else:
            status = HealthStatus.HEALTHY
            message = "Database connections healthy"
            
        return {
            "status": status,
            "message": message,
            "details": {
                "connections": f"{active}/{max_size}",
                "utilization": f"{utilization*100:.1f}%"
            }
        }
        
    async def check_query_performance(self, query_metrics: QueryMetrics) -> Dict[str, Any]:
        """Check query performance health."""
        stats = query_metrics.get_stats()
        
        if stats["success_rate"] < 0.9:
            status = HealthStatus.UNHEALTHY
            message = "High query failure rate"
        elif stats.get("percentiles", {}).get("p95", 0) > 1.0:
            status = HealthStatus.DEGRADED
            message = "High query latency"
        else:
            status = HealthStatus.HEALTHY
            message = "Query performance normal"
            
        return {
            "status": status,
            "message": message,
            "details": {
                "success_rate": f"{stats['success_rate']*100:.1f}%",
                "p95_latency": f"{stats.get('percentiles', {}).get('p95', 0)*1000:.0f}ms"
            }
        }
        
    async def check_cache(self, cache_metrics: CacheMetrics) -> Dict[str, Any]:
        """Check cache effectiveness."""
        stats = cache_metrics.get_stats()
        
        if stats["hit_rate"] < 0.5 and stats["hits"] + stats["misses"] > 100:
            status = HealthStatus.DEGRADED
            message = "Low cache hit rate"
        else:
            status = HealthStatus.HEALTHY
            message = "Cache operating normally"
            
        return {
            "status": status,
            "message": message,
            "details": {
                "hit_rate": f"{stats['hit_rate']*100:.1f}%",
                "size": stats["size"]
            }
        }
        
    async def check_errors(self, error_metrics: ErrorMetrics) -> Dict[str, Any]:
        """Check error rates."""
        stats = error_metrics.get_stats()
        error_rate = stats["error_rate_per_hour"]
        
        if error_rate > 500:
            status = HealthStatus.UNHEALTHY
            message = "Very high error rate"
        elif error_rate > 100:
            status = HealthStatus.DEGRADED
            message = "Elevated error rate"
        else:
            status = HealthStatus.HEALTHY
            message = "Error rate within normal range"
            
        return {
            "status": status,
            "message": message,
            "details": {
                "error_rate": f"{error_rate:.0f}/hour",
                "total_errors": stats["total_errors"]
            }
        }
        
    async def check_health(
        self,
        query_metrics: Optional[QueryMetrics] = None,
        pool_metrics: Optional[ConnectionPoolMetrics] = None,
        cache_metrics: Optional[CacheMetrics] = None,
        error_metrics: Optional[ErrorMetrics] = None
    ) -> Dict[str, Any]:
        """Run all health checks."""
        overall_status = HealthStatus.HEALTHY
        checks = {}
        
        # Run applicable checks
        if pool_metrics and "database" in self._checks:
            result = await self._checks["database"](pool_metrics)
            checks["database"] = result
            if result["status"].value > overall_status.value:
                overall_status = result["status"]
                
        if query_metrics and "query_performance" in self._checks:
            result = await self._checks["query_performance"](query_metrics)
            checks["query_performance"] = result
            if result["status"].value > overall_status.value:
                overall_status = result["status"]
                
        if cache_metrics and "cache" in self._checks:
            result = await self._checks["cache"](cache_metrics)
            checks["cache"] = result
            if result["status"].value > overall_status.value:
                overall_status = result["status"]
                
        if error_metrics and "errors" in self._checks:
            result = await self._checks["errors"](error_metrics)
            checks["errors"] = result
            if result["status"].value > overall_status.value:
                overall_status = result["status"]
                
        # Run custom checks without metrics
        for name, check_func in self._checks.items():
            if name not in ["database", "query_performance", "cache", "errors"]:
                try:
                    result = await check_func()
                    checks[name] = result
                    if result.get("status", HealthStatus.HEALTHY).value > overall_status.value:
                        overall_status = result["status"]
                except Exception as e:
                    checks[name] = {
                        "status": HealthStatus.UNHEALTHY,
                        "message": f"Check failed: {str(e)}"
                    }
                    overall_status = HealthStatus.UNHEALTHY
                    
        return {
            "status": overall_status.value,
            "timestamp": datetime.now().isoformat(),
            "checks": checks
        }


class MetricsCollector:
    """Central metrics collection system."""
    
    def __init__(self, pool_size: int = 10):
        self.query_metrics = QueryMetrics()
        self.pool_metrics = ConnectionPoolMetrics(pool_size)
        self.cache_metrics = CacheMetrics()
        self.error_metrics = ErrorMetrics()
        self.start_time = time.time()
        
    def collect_all(self) -> Dict[str, Any]:
        """Collect all metrics."""
        uptime = time.time() - self.start_time
        
        return {
            "uptime_seconds": uptime,
            "timestamp": datetime.now().isoformat(),
            "queries": self.query_metrics.get_stats(),
            "connection_pool": self.pool_metrics.get_stats(),
            "cache": self.cache_metrics.get_stats(),
            "errors": self.error_metrics.get_stats()
        }
        
    def export_prometheus(self) -> str:
        """Export metrics in Prometheus format."""
        lines = []
        metrics = self.collect_all()
        
        # Query metrics
        query_stats = metrics["queries"]
        lines.append("# HELP mysql_queries_total Total number of queries executed")
        lines.append("# TYPE mysql_queries_total counter")
        lines.append(f"mysql_queries_total {query_stats['total_queries']}")
        
        lines.append("# HELP mysql_queries_success_total Successful queries")
        lines.append("# TYPE mysql_queries_success_total counter")
        lines.append(f"mysql_queries_success_total {query_stats['successful_queries']}")
        
        lines.append("# HELP mysql_queries_failed_total Failed queries")
        lines.append("# TYPE mysql_queries_failed_total counter")
        lines.append(f"mysql_queries_failed_total {query_stats['failed_queries']}")
        
        # Query latency percentiles
        if query_stats.get("percentiles"):
            for percentile, value in query_stats["percentiles"].items():
                lines.append(f"# HELP mysql_query_duration_seconds Query duration {percentile}")
                lines.append(f"# TYPE mysql_query_duration_seconds gauge")
                lines.append(f"mysql_query_duration_seconds{{quantile=\"{percentile[1:]}\"}} {value}")
        
        # Connection pool metrics
        pool_stats = metrics["connection_pool"]
        lines.append("# HELP mysql_pool_connections_active Active connections")
        lines.append("# TYPE mysql_pool_connections_active gauge")
        lines.append(f"mysql_pool_connections_active {pool_stats['active_connections']}")
        
        lines.append("# HELP mysql_pool_utilization Pool utilization ratio")
        lines.append("# TYPE mysql_pool_utilization gauge")
        lines.append(f"mysql_pool_utilization {pool_stats['utilization']}")
        
        # Cache metrics
        cache_stats = metrics["cache"]
        lines.append("# HELP mysql_cache_hits_total Cache hits")
        lines.append("# TYPE mysql_cache_hits_total counter")
        lines.append(f"mysql_cache_hits_total {cache_stats['hits']}")
        
        lines.append("# HELP mysql_cache_misses_total Cache misses")
        lines.append("# TYPE mysql_cache_misses_total counter")
        lines.append(f"mysql_cache_misses_total {cache_stats['misses']}")
        
        lines.append("# HELP mysql_cache_hit_ratio Cache hit ratio")
        lines.append("# TYPE mysql_cache_hit_ratio gauge")
        lines.append(f"mysql_cache_hit_ratio {cache_stats['hit_rate']}")
        
        # Error metrics
        error_stats = metrics["errors"]
        lines.append("# HELP mysql_errors_total Total errors")
        lines.append("# TYPE mysql_errors_total counter")
        lines.append(f"mysql_errors_total {error_stats['total_errors']}")
        
        lines.append("# HELP mysql_error_rate_per_hour Error rate per hour")
        lines.append("# TYPE mysql_error_rate_per_hour gauge")
        lines.append(f"mysql_error_rate_per_hour {error_stats['error_rate_per_hour']}")
        
        # System uptime
        lines.append("# HELP mysql_uptime_seconds Server uptime")
        lines.append("# TYPE mysql_uptime_seconds counter")
        lines.append(f"mysql_uptime_seconds {metrics['uptime_seconds']}")
        
        return "\n".join(lines)


class EnhancedJSONFormatter(logging.Formatter):
    """Enhanced JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "location": {
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName
            },
            "process": record.process,
            "thread": record.thread
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
            
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ["name", "msg", "args", "created", "filename", "funcName",
                          "levelname", "levelno", "lineno", "module", "msecs",
                          "pathname", "process", "processName", "relativeCreated",
                          "thread", "threadName", "exc_info", "exc_text", "stack_info"]:
                log_data[key] = value
                
        return json.dumps(log_data)


class LogRotator:
    """Log rotation functionality."""
    
    def __init__(self, filename: str, max_bytes: int = 10485760, backup_count: int = 5):
        """
        Initialize log rotator.
        
        Args:
            filename: Log file path
            max_bytes: Maximum file size before rotation (default 10MB)
            backup_count: Number of backup files to keep
        """
        self.filename = filename
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        
    def should_rotate(self) -> bool:
        """Check if log file should be rotated."""
        try:
            import os
            file_size = os.path.getsize(self.filename)
            return file_size >= self.max_bytes
        except (FileNotFoundError, OSError):
            return False
            
    def rotate(self):
        """Perform log rotation."""
        base_path = Path(self.filename)
        
        # Remove oldest backup if at limit
        oldest = base_path.with_suffix(f".{self.backup_count}")
        if oldest.exists():
            oldest.unlink()
            
        # Rename existing backups
        for i in range(self.backup_count - 1, 0, -1):
            old_backup = base_path.with_suffix(f".{i}")
            new_backup = base_path.with_suffix(f".{i + 1}")
            if old_backup.exists():
                old_backup.rename(new_backup)
                
        # Rename current file to .1
        if base_path.exists():
            base_path.rename(base_path.with_suffix(".1"))