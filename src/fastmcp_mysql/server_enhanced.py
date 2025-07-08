"""Enhanced FastMCP server with observability features."""

import asyncio
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP, Context

from .config import Settings
from .connection import create_connection_manager, ConnectionManager
from .tools.query import set_connection_manager, set_security_manager
from .security import SecurityManager
from .cache.manager import CacheManager

# Observability imports
from .observability import (
    setup_enhanced_logging,
    ContextLogger,
    MetricsLogger,
    request_context,
    MetricsCollector,
    get_metrics_collector,
    HealthChecker,
    TracingManager,
    setup_tracing,
    trace_query,
)


# Global instances
_health_checker: Optional[HealthChecker] = None
_metrics_logger: Optional[MetricsLogger] = None


def setup_observability(settings: Settings) -> None:
    """Set up observability systems."""
    # Set up enhanced logging
    log_dir = Path(settings.log_dir) if hasattr(settings, 'log_dir') else Path("/var/log/fastmcp-mysql")
    setup_enhanced_logging(
        log_level=settings.log_level,
        log_dir=log_dir,
        enable_file_logging=getattr(settings, 'enable_file_logging', True),
        enable_console_logging=True
    )
    
    # Set up tracing
    otlp_endpoint = getattr(settings, 'otlp_endpoint', None)
    if otlp_endpoint:
        setup_tracing(
            service_name="fastmcp-mysql",
            otlp_endpoint=otlp_endpoint,
            enabled=getattr(settings, 'enable_tracing', True)
        )
    
    # Create metrics logger
    global _metrics_logger
    logger = logging.getLogger("fastmcp_mysql.metrics")
    _metrics_logger = MetricsLogger(logger)


async def create_enhanced_server() -> FastMCP:
    """Create FastMCP server with observability features.
    
    Returns:
        Configured FastMCP server instance
    """
    # Load settings
    settings = Settings()
    
    # Set up observability
    setup_observability(settings)
    
    # Create logger
    logger = ContextLogger(logging.getLogger(__name__))
    
    # Create server
    mcp = FastMCP("MySQL Server")
    
    # Initialize components
    connection_manager = await create_connection_manager(settings)
    set_connection_manager(connection_manager)
    
    # Initialize cache if enabled
    cache_manager = None
    if settings.cache_enabled:
        from .cache.factory import create_cache_manager
        cache_manager = create_cache_manager(settings)
    
    # Initialize security
    from .server import setup_security
    security_manager = setup_security(settings)
    if security_manager:
        set_security_manager(security_manager)
    
    # Create health checker
    global _health_checker
    _health_checker = HealthChecker(connection_manager, cache_manager)
    
    # Get metrics collector
    metrics_collector = get_metrics_collector()
    
    # Log server startup
    logger.info(
        "FastMCP MySQL server started",
        extra={
            "config": settings.to_dict_safe(),
            "observability": {
                "logging": "enhanced",
                "metrics": "enabled",
                "health_checks": "enabled",
                "tracing": bool(getattr(settings, 'otlp_endpoint', None)),
            }
        }
    )
    
    # Register tools
    
    @mcp.tool
    @trace_query
    async def mysql_query(
        query: str,
        params: Optional[List[Any]] = None,
        database: Optional[str] = None,
        context: Optional[Context] = None
    ) -> Dict[str, Any]:
        """Execute a MySQL query with observability.
        
        Args:
            query: SQL query to execute
            params: Optional query parameters
            database: Optional database name
            context: FastMCP context
            
        Returns:
            Query execution result
        """
        # Create request context
        request_id = getattr(context, 'request_id', None) if context else None
        
        with request_context(
            request_id=request_id,
            user_id=getattr(context, 'user_id', None) if context else None,
            session_id=getattr(context, 'session_id', None) if context else None,
        ):
            start_time = time.time()
            
            try:
                # Execute query
                from .tools.query import mysql_query as _mysql_query
                result = await _mysql_query(query, params, database, context)
                
                # Record metrics
                duration_ms = (time.time() - start_time) * 1000
                query_type = _get_query_type(query)
                
                metrics_collector.record_query(
                    query_type=query_type,
                    duration_ms=duration_ms,
                    success=result.get("success", False),
                    query=query
                )
                
                # Log metrics
                if _metrics_logger:
                    _metrics_logger.log_query_metrics(
                        query=query,
                        duration_ms=duration_ms,
                        rows_affected=result.get("metadata", {}).get("rows_affected", 0),
                        success=result.get("success", False),
                        error=result.get("error")
                    )
                
                return result
                
            except Exception as e:
                # Record error
                duration_ms = (time.time() - start_time) * 1000
                metrics_collector.record_error("query_error", str(e), {"query": query[:100]})
                
                # Log error metrics
                if _metrics_logger:
                    _metrics_logger.log_query_metrics(
                        query=query,
                        duration_ms=duration_ms,
                        rows_affected=0,
                        success=False,
                        error=str(e)
                    )
                
                raise
    
    @mcp.tool
    async def mysql_health() -> Dict[str, Any]:
        """Get health status of MySQL server.
        
        Returns:
            Health check results
        """
        if not _health_checker:
            return {
                "status": "unknown",
                "message": "Health checker not initialized"
            }
        
        result = await _health_checker.check_all()
        return result.to_dict()
    
    @mcp.tool
    async def mysql_metrics() -> Dict[str, Any]:
        """Get current metrics.
        
        Returns:
            Current metrics data
        """
        return metrics_collector.export_metrics()
    
    @mcp.tool
    async def mysql_metrics_prometheus() -> str:
        """Get metrics in Prometheus format.
        
        Returns:
            Metrics in Prometheus text format
        """
        return metrics_collector.export_prometheus()
    
    # Background tasks
    
    async def update_connection_metrics():
        """Periodically update connection pool metrics."""
        while True:
            try:
                pool_metrics = connection_manager.get_pool_metrics()
                metrics_collector.update_connection_pool(
                    total=pool_metrics["total_connections"],
                    active=pool_metrics["used_connections"],
                    max_size=pool_metrics["max_size"]
                )
                
                if _metrics_logger:
                    _metrics_logger.log_connection_metrics(
                        total=pool_metrics["total_connections"],
                        free=pool_metrics["free_connections"],
                        used=pool_metrics["used_connections"]
                    )
                
                await asyncio.sleep(30)  # Update every 30 seconds
            except Exception as e:
                logger.error(f"Failed to update connection metrics: {e}")
                await asyncio.sleep(60)  # Wait longer on error
    
    async def update_cache_metrics():
        """Periodically update cache metrics."""
        if not cache_manager:
            return
            
        while True:
            try:
                # Update cache size
                metrics = metrics_collector.cache_metrics
                metrics.update_size(
                    current=cache_manager.size(),
                    max_size=cache_manager.max_size
                )
                
                if _metrics_logger:
                    _metrics_logger.log_cache_metrics(
                        hits=metrics.hits,
                        misses=metrics.misses,
                        evictions=metrics.evictions,
                        size=metrics.current_size
                    )
                
                await asyncio.sleep(60)  # Update every minute
            except Exception as e:
                logger.error(f"Failed to update cache metrics: {e}")
                await asyncio.sleep(120)  # Wait longer on error
    
    # Start background tasks
    asyncio.create_task(update_connection_metrics())
    if cache_manager:
        asyncio.create_task(update_cache_metrics())
    
    return mcp


def _get_query_type(query: str) -> str:
    """Extract query type from SQL query."""
    query = query.strip().upper()
    if query.startswith("SELECT"):
        return "SELECT"
    elif query.startswith("INSERT"):
        return "INSERT"
    elif query.startswith("UPDATE"):
        return "UPDATE"
    elif query.startswith("DELETE"):
        return "DELETE"
    elif query.startswith(("CREATE", "DROP", "ALTER")):
        return "DDL"
    else:
        return "OTHER"