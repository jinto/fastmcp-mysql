"""Example of using FastMCP MySQL with observability features."""

import asyncio
import logging
from pathlib import Path

from fastmcp_mysql.config import Settings, LogLevel
from fastmcp_mysql.server_enhanced import create_enhanced_server
from fastmcp_mysql.observability import (
    ContextLogger,
    request_context,
    get_metrics_collector,
    setup_tracing,
)


async def main():
    """Run example with observability features."""
    # Configure settings with observability options
    import os
    os.environ["MYSQL_USER"] = "root"
    os.environ["MYSQL_PASSWORD"] = "password"
    os.environ["MYSQL_DB"] = "test"
    os.environ["MYSQL_HOST"] = "localhost"
    os.environ["MYSQL_LOG_LEVEL"] = "DEBUG"
    
    # Additional observability settings
    os.environ["MYSQL_LOG_DIR"] = "/tmp/fastmcp-mysql-logs"
    os.environ["MYSQL_ENABLE_FILE_LOGGING"] = "true"
    os.environ["MYSQL_OTLP_ENDPOINT"] = "localhost:4317"  # For OpenTelemetry
    os.environ["MYSQL_ENABLE_TRACING"] = "true"
    
    # Create server
    server = await create_enhanced_server()
    
    # Get logger and metrics
    logger = ContextLogger(logging.getLogger(__name__))
    metrics = get_metrics_collector()
    
    # Example 1: Execute queries with context
    print("\n=== Example 1: Queries with Context ===")
    
    with request_context(user_id="user123", session_id="session456"):
        logger.info("Starting query execution")
        
        # Execute a SELECT query
        result = await server.mysql_query(
            "SELECT * FROM users WHERE id = %s",
            params=[1]
        )
        print(f"Query result: {result}")
        
        # Execute an INSERT (will fail if not allowed)
        try:
            result = await server.mysql_query(
                "INSERT INTO users (name, email) VALUES (%s, %s)",
                params=["John Doe", "john@example.com"]
            )
        except Exception as e:
            logger.error(f"Insert failed: {e}")
    
    # Example 2: Health checks
    print("\n=== Example 2: Health Checks ===")
    
    health = await server.mysql_health()
    print(f"Health status: {health['status']}")
    print("Components:")
    for component in health['components']:
        print(f"  - {component['name']}: {component['status']} - {component['message']}")
    
    # Example 3: Metrics
    print("\n=== Example 3: Metrics ===")
    
    metrics_data = await server.mysql_metrics()
    print(f"Total queries: {metrics_data['query']['total']}")
    print(f"Query error rate: {metrics_data['query']['error_rate']:.1f}%")
    print(f"Cache hit rate: {metrics_data['cache']['hit_rate_percent']:.1f}%")
    print(f"Connection pool utilization: {metrics_data['connection_pool']['utilization_percent']:.1f}%")
    
    # Example 4: Prometheus metrics
    print("\n=== Example 4: Prometheus Metrics ===")
    
    prometheus_metrics = await server.mysql_metrics_prometheus()
    print("Sample Prometheus metrics:")
    print(prometheus_metrics[:500] + "...")  # Show first 500 chars
    
    # Example 5: Simulate load and check metrics
    print("\n=== Example 5: Load Test ===")
    
    async def run_queries(count: int):
        """Run multiple queries."""
        for i in range(count):
            try:
                await server.mysql_query(f"SELECT {i} as num")
            except Exception:
                pass
            await asyncio.sleep(0.01)  # Small delay
    
    # Run some queries
    await run_queries(50)
    
    # Check updated metrics
    metrics_data = await server.mysql_metrics()
    percentiles = metrics_data['query']['duration_percentiles_ms']
    print(f"\nQuery performance percentiles:")
    print(f"  p50: {percentiles['p50']:.1f}ms")
    print(f"  p90: {percentiles['p90']:.1f}ms")
    print(f"  p95: {percentiles['p95']:.1f}ms")
    print(f"  p99: {percentiles['p99']:.1f}ms")
    
    # Example 6: Custom metrics
    print("\n=== Example 6: Custom Metrics ===")
    
    # Register custom metric
    metrics.register_custom_metric("app_version", "1.2.3")
    metrics.register_custom_metric("environment", "development")
    
    # Get metrics with custom values
    metrics_data = await server.mysql_metrics()
    print(f"Custom metrics: {metrics_data['custom']}")
    
    # Example 7: Error tracking
    print("\n=== Example 7: Error Tracking ===")
    
    # Simulate some errors
    for i in range(5):
        try:
            await server.mysql_query("INVALID SQL QUERY")
        except Exception:
            pass
    
    # Check error metrics
    metrics_data = await server.mysql_metrics()
    print(f"Total errors: {sum(metrics_data['errors']['by_type'].values())}")
    print(f"Error types: {list(metrics_data['errors']['by_type'].keys())}")
    print(f"Recent errors: {len(metrics_data['errors']['recent_errors'])}")
    
    # Example 8: Log file check
    print("\n=== Example 8: Log Files ===")
    
    log_dir = Path("/tmp/fastmcp-mysql-logs")
    if log_dir.exists():
        log_files = list(log_dir.glob("*.log"))
        print(f"Log files created: {[f.name for f in log_files]}")
        
        # Show sample from main log
        main_log = log_dir / "fastmcp-mysql.log"
        if main_log.exists():
            with open(main_log) as f:
                lines = f.readlines()
                print(f"\nSample log entries ({len(lines)} total):")
                for line in lines[:3]:  # Show first 3 lines
                    print(f"  {line.strip()}")


if __name__ == "__main__":
    asyncio.run(main())