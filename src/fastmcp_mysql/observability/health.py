"""Health check system for FastMCP MySQL server."""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, Any, Optional, List, Callable, Awaitable

from ..connection import ConnectionManager
from ..cache.manager import CacheManager
from .metrics import get_metrics_collector


class HealthStatus(Enum):
    """Health status levels."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class ComponentHealth:
    """Health status of a component."""
    name: str
    status: HealthStatus
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    last_check: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    check_duration_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "details": self.details,
            "last_check": self.last_check.isoformat(),
            "check_duration_ms": self.check_duration_ms,
        }


@dataclass
class HealthCheckResult:
    """Overall health check result."""
    status: HealthStatus
    components: List[ComponentHealth]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    version: str = "1.0.0"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status": self.status.value,
            "timestamp": self.timestamp.isoformat(),
            "version": self.version,
            "components": [c.to_dict() for c in self.components],
            "summary": {
                "total_components": len(self.components),
                "healthy": sum(1 for c in self.components if c.status == HealthStatus.HEALTHY),
                "degraded": sum(1 for c in self.components if c.status == HealthStatus.DEGRADED),
                "unhealthy": sum(1 for c in self.components if c.status == HealthStatus.UNHEALTHY),
            }
        }


class HealthChecker:
    """Health check manager for the application."""
    
    def __init__(self, 
                 connection_manager: Optional[ConnectionManager] = None,
                 cache_manager: Optional[CacheManager] = None):
        """Initialize health checker.
        
        Args:
            connection_manager: Database connection manager
            cache_manager: Cache manager
        """
        self.connection_manager = connection_manager
        self.cache_manager = cache_manager
        self.metrics_collector = get_metrics_collector()
        self._custom_checks: Dict[str, Callable[[], Awaitable[ComponentHealth]]] = {}
        self._thresholds = {
            "query_error_rate": 10.0,  # 10% error rate threshold
            "connection_utilization": 90.0,  # 90% pool utilization threshold
            "cache_hit_rate": 50.0,  # 50% minimum cache hit rate
            "slow_query_threshold_ms": 1000.0,  # 1 second slow query threshold
        }
    
    def set_threshold(self, name: str, value: float):
        """Set a health check threshold.
        
        Args:
            name: Threshold name
            value: Threshold value
        """
        self._thresholds[name] = value
    
    def register_check(self, name: str, check_func: Callable[[], Awaitable[ComponentHealth]]):
        """Register a custom health check.
        
        Args:
            name: Check name
            check_func: Async function that returns ComponentHealth
        """
        self._custom_checks[name] = check_func
    
    async def check_database(self) -> ComponentHealth:
        """Check database connectivity and performance."""
        start_time = time.time()
        
        try:
            if not self.connection_manager:
                return ComponentHealth(
                    name="database",
                    status=HealthStatus.UNHEALTHY,
                    message="Connection manager not initialized",
                    check_duration_ms=(time.time() - start_time) * 1000
                )
            
            # Check basic connectivity
            is_healthy = await self.connection_manager.health_check()
            
            if not is_healthy:
                return ComponentHealth(
                    name="database",
                    status=HealthStatus.UNHEALTHY,
                    message="Database connection failed",
                    check_duration_ms=(time.time() - start_time) * 1000
                )
            
            # Get pool metrics
            pool_metrics = self.connection_manager.get_pool_metrics()
            
            # Check pool utilization
            utilization = (pool_metrics["used_connections"] / pool_metrics["max_size"] * 100) \
                         if pool_metrics["max_size"] > 0 else 0
            
            status = HealthStatus.HEALTHY
            message = "Database is healthy"
            
            if utilization > self._thresholds["connection_utilization"]:
                status = HealthStatus.DEGRADED
                message = f"High connection pool utilization: {utilization:.1f}%"
            
            return ComponentHealth(
                name="database",
                status=status,
                message=message,
                details={
                    "pool_metrics": pool_metrics,
                    "utilization_percent": utilization,
                },
                check_duration_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            return ComponentHealth(
                name="database",
                status=HealthStatus.UNHEALTHY,
                message=f"Health check failed: {str(e)}",
                check_duration_ms=(time.time() - start_time) * 1000
            )
    
    async def check_cache(self) -> ComponentHealth:
        """Check cache system health."""
        start_time = time.time()
        
        try:
            if not self.cache_manager:
                return ComponentHealth(
                    name="cache",
                    status=HealthStatus.HEALTHY,
                    message="Cache not configured",
                    check_duration_ms=(time.time() - start_time) * 1000
                )
            
            # Get cache metrics
            metrics = self.metrics_collector.cache_metrics
            hit_rate = metrics.get_hit_rate()
            utilization = metrics.get_utilization()
            
            status = HealthStatus.HEALTHY
            message = "Cache is healthy"
            
            # Check hit rate
            if hit_rate < self._thresholds["cache_hit_rate"] and metrics.hits + metrics.misses > 100:
                status = HealthStatus.DEGRADED
                message = f"Low cache hit rate: {hit_rate:.1f}%"
            
            # Check if cache is full
            if utilization >= 100:
                status = HealthStatus.DEGRADED
                message = "Cache is full"
            
            return ComponentHealth(
                name="cache",
                status=status,
                message=message,
                details={
                    "hit_rate_percent": hit_rate,
                    "utilization_percent": utilization,
                    "hits": metrics.hits,
                    "misses": metrics.misses,
                    "evictions": metrics.evictions,
                    "size": metrics.current_size,
                },
                check_duration_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            return ComponentHealth(
                name="cache",
                status=HealthStatus.UNHEALTHY,
                message=f"Health check failed: {str(e)}",
                check_duration_ms=(time.time() - start_time) * 1000
            )
    
    async def check_query_performance(self) -> ComponentHealth:
        """Check query performance metrics."""
        start_time = time.time()
        
        try:
            # Get query metrics
            metrics = self.metrics_collector.query_metrics
            error_rate = metrics.get_error_rate()
            percentiles = metrics.get_percentiles()
            
            status = HealthStatus.HEALTHY
            message = "Query performance is healthy"
            
            # Check error rate
            if error_rate > self._thresholds["query_error_rate"]:
                status = HealthStatus.UNHEALTHY
                message = f"High query error rate: {error_rate:.1f}%"
            
            # Check slow queries
            elif percentiles["p95"] > self._thresholds["slow_query_threshold_ms"]:
                status = HealthStatus.DEGRADED
                message = f"Slow query performance: p95={percentiles['p95']:.0f}ms"
            
            return ComponentHealth(
                name="query_performance",
                status=status,
                message=message,
                details={
                    "total_queries": metrics.total_queries,
                    "error_rate_percent": error_rate,
                    "percentiles_ms": percentiles,
                    "slow_queries_count": len(metrics.slow_queries),
                },
                check_duration_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            return ComponentHealth(
                name="query_performance",
                status=HealthStatus.UNHEALTHY,
                message=f"Health check failed: {str(e)}",
                check_duration_ms=(time.time() - start_time) * 1000
            )
    
    async def check_errors(self) -> ComponentHealth:
        """Check error rates."""
        start_time = time.time()
        
        try:
            # Get error metrics
            error_rates = self.metrics_collector.error_metrics.get_error_rate(60)  # Last minute
            total_errors = sum(self.metrics_collector.error_metrics.errors_by_type.values())
            
            status = HealthStatus.HEALTHY
            message = "Error rates are normal"
            
            # Check if any error rate is too high
            high_error_types = [
                error_type for error_type, rate in error_rates.items()
                if rate > 10  # More than 10 errors per minute
            ]
            
            if high_error_types:
                status = HealthStatus.DEGRADED
                message = f"High error rate for: {', '.join(high_error_types)}"
            
            return ComponentHealth(
                name="errors",
                status=status,
                message=message,
                details={
                    "total_errors": total_errors,
                    "error_rates_per_minute": error_rates,
                    "error_types": dict(self.metrics_collector.error_metrics.errors_by_type),
                },
                check_duration_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            return ComponentHealth(
                name="errors",
                status=HealthStatus.UNHEALTHY,
                message=f"Health check failed: {str(e)}",
                check_duration_ms=(time.time() - start_time) * 1000
            )
    
    async def check_all(self) -> HealthCheckResult:
        """Run all health checks."""
        components = []
        
        # Run built-in checks
        checks = [
            self.check_database(),
            self.check_cache(),
            self.check_query_performance(),
            self.check_errors(),
        ]
        
        # Add custom checks
        for name, check_func in self._custom_checks.items():
            checks.append(check_func())
        
        # Run all checks concurrently
        results = await asyncio.gather(*checks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, ComponentHealth):
                components.append(result)
            else:
                # Handle exceptions
                components.append(ComponentHealth(
                    name="unknown",
                    status=HealthStatus.UNHEALTHY,
                    message=f"Check failed: {str(result)}",
                ))
        
        # Determine overall status
        unhealthy_count = sum(1 for c in components if c.status == HealthStatus.UNHEALTHY)
        degraded_count = sum(1 for c in components if c.status == HealthStatus.DEGRADED)
        
        if unhealthy_count > 0:
            overall_status = HealthStatus.UNHEALTHY
        elif degraded_count > 0:
            overall_status = HealthStatus.DEGRADED
        else:
            overall_status = HealthStatus.HEALTHY
        
        return HealthCheckResult(
            status=overall_status,
            components=components,
        )
    
    async def check_liveness(self) -> bool:
        """Simple liveness check.
        
        Returns:
            True if the service is alive
        """
        # For FastMCP, being able to respond means we're alive
        return True
    
    async def check_readiness(self) -> bool:
        """Readiness check.
        
        Returns:
            True if the service is ready to handle requests
        """
        # Check if critical components are healthy
        if self.connection_manager:
            return await self.connection_manager.health_check()
        return True