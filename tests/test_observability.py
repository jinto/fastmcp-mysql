"""Tests for observability features."""

import asyncio
import json
import logging
import tempfile
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from fastmcp_mysql.config import LogLevel
from fastmcp_mysql.observability import (
    EnhancedJSONFormatter,
    ContextLogger,
    MetricsLogger,
    request_context,
    RequestContext,
    MetricsCollector,
    QueryMetrics,
    ConnectionPoolMetrics,
    CacheMetrics,
    ErrorMetrics,
    HealthChecker,
    HealthStatus,
    ComponentHealth,
    TracingManager,
    SpanKind,
)


class TestEnhancedJSONFormatter:
    """Test enhanced JSON formatter."""
    
    def test_basic_formatting(self):
        """Test basic log formatting."""
        formatter = EnhancedJSONFormatter(include_hostname=False, include_process_info=False)
        
        # Create log record
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
            func="test_function"
        )
        
        # Format and parse
        output = formatter.format(record)
        data = json.loads(output)
        
        assert data["level"] == "INFO"
        assert data["logger"] == "test.logger"
        assert data["message"] == "Test message"
        assert data["location"]["file"] == "test.py"
        assert data["location"]["line"] == 42
        assert data["location"]["function"] == "test_function"
    
    def test_with_context(self):
        """Test formatting with request context."""
        formatter = EnhancedJSONFormatter()
        
        # Set context
        context = RequestContext(
            request_id="req123",
            user_id="user456",
            session_id="session789"
        )
        
        with patch.object(threading.current_thread(), 'request_context', context):
            record = logging.LogRecord(
                name="test",
                level=logging.INFO,
                pathname="test.py",
                lineno=1,
                msg="Test",
                args=(),
                exc_info=None
            )
            
            output = formatter.format(record)
            data = json.loads(output)
            
            assert data["context"]["request_id"] == "req123"
            assert data["context"]["user_id"] == "user456"
            assert data["context"]["session_id"] == "session789"
    
    def test_with_exception(self):
        """Test formatting with exception info."""
        formatter = EnhancedJSONFormatter()
        
        try:
            raise ValueError("Test error")
        except ValueError:
            import sys
            exc_info = sys.exc_info()
        
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="Error occurred",
            args=(),
            exc_info=exc_info
        )
        
        output = formatter.format(record)
        data = json.loads(output)
        
        assert data["exception"]["type"] == "ValueError"
        assert data["exception"]["message"] == "Test error"
        assert "Traceback" in data["exception"]["traceback"]


class TestContextLogger:
    """Test context logger."""
    
    def test_context_logging(self):
        """Test logging with context."""
        # Create mock logger
        mock_logger = Mock()
        context_logger = ContextLogger(mock_logger)
        
        # Log with context
        with request_context(request_id="test123", user_id="user456"):
            context_logger.info("Test message", extra={"custom": "value"})
        
        # Check call
        mock_logger.log.assert_called_once()
        call_args = mock_logger.log.call_args
        
        assert call_args[0][0] == logging.INFO
        assert call_args[0][1] == "Test message"
        assert call_args[1]["extra"]["request_id"] == "test123"
        assert call_args[1]["extra"]["user_id"] == "user456"
        assert call_args[1]["extra"]["custom"] == "value"


class TestMetricsLogger:
    """Test metrics logger."""
    
    def test_query_metrics_logging(self):
        """Test query metrics logging."""
        mock_logger = Mock()
        metrics_logger = MetricsLogger(mock_logger)
        
        metrics_logger.log_query_metrics(
            query="SELECT * FROM users",
            duration_ms=123.45,
            rows_affected=10,
            success=True
        )
        
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        
        assert call_args[0][0] == "query_executed"
        metrics = call_args[1]["extra"]["metrics"]
        assert metrics["type"] == "query"
        assert metrics["duration_ms"] == 123.45
        assert metrics["rows_affected"] == 10
        assert metrics["success"] is True


class TestQueryMetrics:
    """Test query metrics."""
    
    def test_record_query(self):
        """Test recording query metrics."""
        metrics = QueryMetrics()
        
        # Record successful query
        metrics.record_query("SELECT", 100.0, True, "SELECT * FROM users")
        
        assert metrics.total_queries == 1
        assert metrics.successful_queries == 1
        assert metrics.failed_queries == 0
        assert metrics.queries_by_type["SELECT"] == 1
        assert len(metrics.query_duration_ms) == 1
        assert metrics.query_duration_ms[0] == 100.0
    
    def test_slow_query_tracking(self):
        """Test slow query tracking."""
        metrics = QueryMetrics()
        
        # Record slow query
        metrics.record_query("SELECT", 2000.0, True, "SELECT * FROM large_table", threshold_ms=1000)
        
        assert len(metrics.slow_queries) == 1
        assert metrics.slow_queries[0]["duration_ms"] == 2000.0
        assert "SELECT * FROM large_table" in metrics.slow_queries[0]["query"]
    
    def test_percentiles(self):
        """Test percentile calculations."""
        metrics = QueryMetrics()
        
        # Record queries with different durations
        durations = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
        for duration in durations:
            metrics.record_query("SELECT", float(duration), True, "query")
        
        percentiles = metrics.get_percentiles()
        
        assert percentiles["p50"] == 50.0  # Median
        assert percentiles["p90"] == 90.0
        assert percentiles["p99"] == 100.0  # Last value for small dataset
    
    def test_error_rate(self):
        """Test error rate calculation."""
        metrics = QueryMetrics()
        
        # Record mix of successful and failed queries
        for _ in range(7):
            metrics.record_query("SELECT", 100.0, True, "query")
        for _ in range(3):
            metrics.record_query("SELECT", 100.0, False, "query")
        
        error_rate = metrics.get_error_rate()
        assert error_rate == 30.0  # 3 out of 10 failed


class TestConnectionPoolMetrics:
    """Test connection pool metrics."""
    
    def test_update_metrics(self):
        """Test updating connection pool metrics."""
        metrics = ConnectionPoolMetrics()
        
        metrics.update(total=10, active=7, max_size=20)
        
        assert metrics.total_connections == 10
        assert metrics.active_connections == 7
        assert metrics.idle_connections == 3
        assert metrics.max_connections == 20
    
    def test_utilization(self):
        """Test utilization calculation."""
        metrics = ConnectionPoolMetrics()
        
        metrics.update(total=10, active=7, max_size=20)
        utilization = metrics.get_utilization()
        
        assert utilization == 35.0  # 7 out of 20 = 35%
    
    def test_wait_time_tracking(self):
        """Test connection wait time tracking."""
        metrics = ConnectionPoolMetrics()
        
        metrics.record_wait_time(50.0)
        metrics.record_wait_time(100.0)
        metrics.record_wait_time(150.0)
        
        avg_wait = metrics.get_avg_wait_time()
        assert avg_wait == 100.0  # Average of 50, 100, 150


class TestCacheMetrics:
    """Test cache metrics."""
    
    def test_hit_rate(self):
        """Test cache hit rate calculation."""
        metrics = CacheMetrics()
        
        # Record hits and misses
        for _ in range(70):
            metrics.record_hit()
        for _ in range(30):
            metrics.record_miss()
        
        hit_rate = metrics.get_hit_rate()
        assert hit_rate == 70.0  # 70 hits out of 100 total
    
    def test_utilization(self):
        """Test cache utilization calculation."""
        metrics = CacheMetrics()
        
        metrics.update_size(current=800, max_size=1000)
        utilization = metrics.get_utilization()
        
        assert utilization == 80.0  # 800 out of 1000 = 80%


class TestErrorMetrics:
    """Test error metrics."""
    
    def test_record_error(self):
        """Test recording errors."""
        metrics = ErrorMetrics()
        
        metrics.record_error("ValueError", "Invalid input", {"query": "SELECT"})
        metrics.record_error("ValueError", "Another error")
        metrics.record_error("TypeError", "Type mismatch")
        
        assert metrics.errors_by_type["ValueError"] == 2
        assert metrics.errors_by_type["TypeError"] == 1
        assert len(metrics.error_timeline) == 3
    
    def test_error_rate(self):
        """Test error rate calculation."""
        metrics = ErrorMetrics()
        
        # Record errors
        for _ in range(5):
            metrics.record_error("QueryError", "Failed query")
            time.sleep(0.01)  # Small delay to spread timestamps
        
        # Calculate rate
        rates = metrics.get_error_rate(window_seconds=1)
        
        # Should have ~5 errors per second = 300 per minute
        assert rates["QueryError"] > 200  # Allow some variance


class TestMetricsCollector:
    """Test metrics collector."""
    
    def test_thread_safety(self):
        """Test thread-safe operations."""
        collector = MetricsCollector()
        
        # Record from multiple threads
        def record_queries():
            for _ in range(10):
                collector.record_query("SELECT", 100.0, True, "query")
        
        import threading
        threads = [threading.Thread(target=record_queries) for _ in range(5)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should have 50 total queries
        assert collector.query_metrics.total_queries == 50
    
    def test_export_metrics(self):
        """Test metrics export."""
        collector = MetricsCollector()
        
        # Record some metrics
        collector.record_query("SELECT", 100.0, True, "query")
        collector.update_connection_pool(10, 5, 20)
        collector.record_cache_hit()
        collector.record_error("TestError", "Test message")
        
        # Export
        metrics = collector.export_metrics()
        
        assert metrics["query"]["total"] == 1
        assert metrics["connection_pool"]["active"] == 5
        assert metrics["cache"]["hits"] == 1
        assert "TestError" in metrics["errors"]["by_type"]
    
    def test_prometheus_export(self):
        """Test Prometheus format export."""
        collector = MetricsCollector()
        
        # Record metrics
        collector.record_query("SELECT", 100.0, True, "query")
        collector.update_connection_pool(10, 5, 20)
        
        # Export
        prometheus = collector.export_prometheus()
        
        assert "mysql_queries_total 1" in prometheus
        assert "mysql_connections_active 5" in prometheus
        assert "# HELP" in prometheus  # Has metric descriptions
        assert "# TYPE" in prometheus  # Has metric types


class TestHealthChecker:
    """Test health checker."""
    
    @pytest.mark.asyncio
    async def test_database_health_check(self):
        """Test database health check."""
        # Mock connection manager
        mock_conn_manager = Mock()
        mock_conn_manager.health_check.return_value = True
        mock_conn_manager.get_pool_metrics.return_value = {
            "used_connections": 5,
            "max_size": 20,
            "total_connections": 10,
            "free_connections": 5,
        }
        
        checker = HealthChecker(connection_manager=mock_conn_manager)
        
        result = await checker.check_database()
        
        assert result.name == "database"
        assert result.status == HealthStatus.HEALTHY
        assert "pool_metrics" in result.details
    
    @pytest.mark.asyncio
    async def test_degraded_database(self):
        """Test degraded database status."""
        # Mock high utilization
        mock_conn_manager = Mock()
        mock_conn_manager.health_check.return_value = True
        mock_conn_manager.get_pool_metrics.return_value = {
            "used_connections": 19,
            "max_size": 20,
            "total_connections": 20,
            "free_connections": 1,
        }
        
        checker = HealthChecker(connection_manager=mock_conn_manager)
        
        result = await checker.check_database()
        
        assert result.status == HealthStatus.DEGRADED
        assert "High connection pool utilization" in result.message
    
    @pytest.mark.asyncio
    async def test_overall_health(self):
        """Test overall health check."""
        # Mock healthy connection
        mock_conn_manager = Mock()
        mock_conn_manager.health_check.return_value = True
        mock_conn_manager.get_pool_metrics.return_value = {
            "used_connections": 5,
            "max_size": 20,
            "total_connections": 10,
            "free_connections": 5,
        }
        
        checker = HealthChecker(connection_manager=mock_conn_manager)
        
        result = await checker.check_all()
        
        assert result.status == HealthStatus.HEALTHY
        assert len(result.components) >= 4  # At least 4 built-in checks
        
        # Check result format
        data = result.to_dict()
        assert "status" in data
        assert "components" in data
        assert "summary" in data


class TestTracingManager:
    """Test tracing manager."""
    
    @pytest.mark.asyncio
    async def test_span_creation(self):
        """Test creating spans."""
        manager = TracingManager(enabled=True)
        
        async with manager.span("test_operation", SpanKind.INTERNAL) as span:
            span.set_attribute("test_key", "test_value")
            span.add_event("test_event", {"detail": "value"})
        
        assert span.operation_name == "test_operation"
        assert span.attributes["test_key"] == "test_value"
        assert len(span.events) == 1
        assert span.end_time is not None
        assert span.duration_ms() > 0
    
    @pytest.mark.asyncio
    async def test_nested_spans(self):
        """Test nested span creation."""
        manager = TracingManager(enabled=True)
        
        async with manager.span("parent") as parent_span:
            async with manager.span("child") as child_span:
                pass
        
        assert child_span.parent_span_id == parent_span.span_id
    
    @pytest.mark.asyncio
    async def test_span_error_handling(self):
        """Test span error handling."""
        manager = TracingManager(enabled=True)
        
        with pytest.raises(ValueError):
            async with manager.span("error_operation") as span:
                raise ValueError("Test error")
        
        assert span.status == "error"
        assert "Test error" in span.attributes.get("status_message", "")
    
    def test_trace_export(self):
        """Test trace export."""
        manager = TracingManager(enabled=True)
        
        # Create some spans
        async def create_spans():
            async with manager.span("operation1"):
                pass
            async with manager.span("operation2"):
                pass
        
        asyncio.run(create_spans())
        
        # Export traces
        export = manager.export_traces()
        
        assert export["service_name"] == "fastmcp-mysql"
        assert export["total_spans"] == 2
        assert len(export["traces"]) > 0