"""Unit tests for monitoring system."""
import pytest
import asyncio
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
import json

from fastmcp_mysql.monitoring import (
    MetricsCollector,
    QueryMetrics,
    ConnectionPoolMetrics,
    CacheMetrics,
    ErrorMetrics,
    HealthChecker,
    HealthStatus,
    LogRotator,
    EnhancedJSONFormatter
)


class TestQueryMetrics:
    """Test query metrics collection."""
    
    def test_query_metrics_creation(self):
        """Test creating query metrics."""
        metrics = QueryMetrics()
        
        assert metrics.total_queries == 0
        assert metrics.successful_queries == 0
        assert metrics.failed_queries == 0
        assert len(metrics.query_times) == 0
        assert len(metrics.slow_queries) == 0
    
    def test_record_query(self):
        """Test recording query execution."""
        metrics = QueryMetrics()
        
        # Record successful query
        metrics.record_query(0.1, success=True)
        assert metrics.total_queries == 1
        assert metrics.successful_queries == 1
        assert metrics.failed_queries == 0
        assert len(metrics.query_times) == 1
        
        # Record failed query
        metrics.record_query(0.05, success=False)
        assert metrics.total_queries == 2
        assert metrics.successful_queries == 1
        assert metrics.failed_queries == 1
    
    def test_record_slow_query(self):
        """Test recording slow queries."""
        metrics = QueryMetrics()
        
        # Record slow query
        metrics.record_query(2.5, success=True, query="SELECT * FROM large_table")
        assert len(metrics.slow_queries) == 1
        assert metrics.slow_queries[0]["query"] == "SELECT * FROM large_table"
        assert metrics.slow_queries[0]["duration"] == 2.5
    
    def test_get_percentiles(self):
        """Test calculating percentiles."""
        metrics = QueryMetrics()
        
        # Record multiple queries
        for duration in [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]:
            metrics.record_query(duration, success=True)
        
        percentiles = metrics.get_percentiles()
        assert percentiles["p50"] == pytest.approx(0.55, rel=0.1)
        assert percentiles["p90"] == pytest.approx(0.91, rel=0.1)
        assert percentiles["p95"] == pytest.approx(0.955, rel=0.1)
        assert percentiles["p99"] == pytest.approx(0.991, rel=0.1)
    
    def test_get_stats(self):
        """Test getting query statistics."""
        metrics = QueryMetrics()
        
        # Record queries
        metrics.record_query(0.1, success=True)
        metrics.record_query(0.2, success=True)
        metrics.record_query(0.3, success=False)
        
        stats = metrics.get_stats()
        assert stats["total_queries"] == 3
        assert stats["successful_queries"] == 2
        assert stats["failed_queries"] == 1
        assert stats["success_rate"] == pytest.approx(0.667, rel=0.01)
        assert stats["average_time"] == pytest.approx(0.2, rel=0.01)


class TestConnectionPoolMetrics:
    """Test connection pool metrics."""
    
    def test_pool_metrics_creation(self):
        """Test creating connection pool metrics."""
        metrics = ConnectionPoolMetrics(max_size=10)
        
        assert metrics.max_size == 10
        assert metrics.active_connections == 0
        assert metrics.idle_connections == 0
        assert metrics.total_acquired == 0
        assert metrics.total_released == 0
    
    def test_update_pool_state(self):
        """Test updating pool state."""
        metrics = ConnectionPoolMetrics(max_size=10)
        
        metrics.update_pool_state(active=5, idle=3)
        assert metrics.active_connections == 5
        assert metrics.idle_connections == 3
    
    def test_record_acquisition(self):
        """Test recording connection acquisition."""
        metrics = ConnectionPoolMetrics(max_size=10)
        
        metrics.record_acquisition(0.05)
        assert metrics.total_acquired == 1
        assert len(metrics.wait_times) == 1
        assert metrics.wait_times[0] == 0.05
    
    def test_record_release(self):
        """Test recording connection release."""
        metrics = ConnectionPoolMetrics(max_size=10)
        
        metrics.record_release()
        assert metrics.total_released == 1
    
    def test_get_stats(self):
        """Test getting pool statistics."""
        metrics = ConnectionPoolMetrics(max_size=10)
        
        metrics.update_pool_state(active=6, idle=2)
        metrics.record_acquisition(0.01)
        metrics.record_acquisition(0.02)
        
        stats = metrics.get_stats()
        assert stats["max_size"] == 10
        assert stats["active_connections"] == 6
        assert stats["idle_connections"] == 2
        assert stats["utilization"] == 0.8
        assert stats["average_wait_time"] == pytest.approx(0.015, rel=0.01)


class TestCacheMetrics:
    """Test cache metrics collection."""
    
    def test_cache_metrics_creation(self):
        """Test creating cache metrics."""
        metrics = CacheMetrics()
        
        assert metrics.hits == 0
        assert metrics.misses == 0
        assert metrics.evictions == 0
        assert metrics.size == 0
    
    def test_record_hit(self):
        """Test recording cache hit."""
        metrics = CacheMetrics()
        
        metrics.record_hit()
        assert metrics.hits == 1
        assert metrics.misses == 0
    
    def test_record_miss(self):
        """Test recording cache miss."""
        metrics = CacheMetrics()
        
        metrics.record_miss()
        assert metrics.hits == 0
        assert metrics.misses == 1
    
    def test_update_size(self):
        """Test updating cache size."""
        metrics = CacheMetrics()
        
        metrics.update_size(100)
        assert metrics.size == 100
    
    def test_record_eviction(self):
        """Test recording cache eviction."""
        metrics = CacheMetrics()
        
        metrics.record_eviction(5)
        assert metrics.evictions == 5
    
    def test_get_stats(self):
        """Test getting cache statistics."""
        metrics = CacheMetrics()
        
        metrics.record_hit()
        metrics.record_hit()
        metrics.record_miss()
        metrics.update_size(50)
        
        stats = metrics.get_stats()
        assert stats["hits"] == 2
        assert stats["misses"] == 1
        assert stats["hit_rate"] == pytest.approx(0.667, rel=0.01)
        assert stats["size"] == 50


class TestErrorMetrics:
    """Test error metrics collection."""
    
    def test_error_metrics_creation(self):
        """Test creating error metrics."""
        metrics = ErrorMetrics()
        
        assert len(metrics.errors_by_type) == 0
        assert len(metrics.error_timeline) == 0
    
    def test_record_error(self):
        """Test recording errors."""
        metrics = ErrorMetrics()
        
        metrics.record_error("DatabaseError", "Connection failed")
        metrics.record_error("ValueError", "Invalid parameter")
        metrics.record_error("DatabaseError", "Timeout")
        
        assert metrics.errors_by_type["DatabaseError"] == 2
        assert metrics.errors_by_type["ValueError"] == 1
        assert len(metrics.error_timeline) == 3
    
    def test_get_error_rate(self):
        """Test calculating error rate."""
        metrics = ErrorMetrics()
        
        # Record errors over time
        base_time = datetime.now() - timedelta(minutes=30)
        for i in range(10):
            metrics.error_timeline.append({
                "timestamp": base_time + timedelta(minutes=i),
                "type": "TestError",
                "message": f"Error {i}"
            })
        
        # Should have 10 errors in last hour
        rate = metrics.get_error_rate()
        assert rate == 10
    
    def test_get_stats(self):
        """Test getting error statistics."""
        metrics = ErrorMetrics()
        
        metrics.record_error("TypeError", "Test error 1")
        metrics.record_error("ValueError", "Test error 2")
        metrics.record_error("TypeError", "Test error 3")
        
        stats = metrics.get_stats()
        assert stats["total_errors"] == 3
        assert len(stats["errors_by_type"]) == 2
        assert stats["errors_by_type"]["TypeError"] == 2
        assert stats["error_rate_per_hour"] >= 0


class TestHealthChecker:
    """Test health checking system."""
    
    @pytest.mark.asyncio
    async def test_health_checker_creation(self):
        """Test creating health checker."""
        checker = HealthChecker()
        
        assert checker is not None
        assert len(checker._checks) > 0  # Should have default checks
    
    @pytest.mark.asyncio
    async def test_database_health_check(self):
        """Test database health check."""
        checker = HealthChecker()
        metrics = Mock(get_stats=Mock(return_value={
            "active_connections": 5,
            "utilization": 0.5
        }))
        
        status = await checker.check_database(metrics)
        assert status["status"] == HealthStatus.HEALTHY
        assert "connections" in status["details"]
    
    @pytest.mark.asyncio
    async def test_query_performance_check(self):
        """Test query performance health check."""
        checker = HealthChecker()
        metrics = Mock(get_stats=Mock(return_value={
            "success_rate": 0.95,
            "percentiles": {"p95": 0.5}
        }))
        
        status = await checker.check_query_performance(metrics)
        assert status["status"] == HealthStatus.HEALTHY
    
    @pytest.mark.asyncio
    async def test_cache_health_check(self):
        """Test cache health check."""
        checker = HealthChecker()
        metrics = Mock(get_stats=Mock(return_value={
            "hit_rate": 0.8,
            "size": 500
        }))
        
        status = await checker.check_cache(metrics)
        assert status["status"] == HealthStatus.HEALTHY
    
    @pytest.mark.asyncio
    async def test_degraded_health(self):
        """Test degraded health status."""
        checker = HealthChecker()
        
        # Mock high error rate
        error_metrics = Mock(get_stats=Mock(return_value={
            "error_rate_per_hour": 150,  # Above warning threshold
            "total_errors": 150
        }))
        
        status = await checker.check_errors(error_metrics)
        assert status["status"] == HealthStatus.DEGRADED
    
    @pytest.mark.asyncio
    async def test_unhealthy_status(self):
        """Test unhealthy status."""
        checker = HealthChecker()
        
        # Mock very high error rate
        error_metrics = Mock(get_stats=Mock(return_value={
            "error_rate_per_hour": 600,  # Above critical threshold
            "total_errors": 600
        }))
        
        status = await checker.check_errors(error_metrics)
        assert status["status"] == HealthStatus.UNHEALTHY
    
    @pytest.mark.asyncio
    async def test_custom_health_check(self):
        """Test registering custom health check."""
        checker = HealthChecker()
        
        async def custom_check():
            return {
                "status": HealthStatus.HEALTHY,
                "details": {"custom": "OK"}
            }
        
        checker.register_check("custom", custom_check)
        
        # Run all checks
        health = await checker.check_health()
        assert "custom" in health["checks"]


class TestMetricsCollector:
    """Test metrics collector."""
    
    def test_metrics_collector_creation(self):
        """Test creating metrics collector."""
        collector = MetricsCollector()
        
        assert collector.query_metrics is not None
        assert collector.pool_metrics is not None
        assert collector.cache_metrics is not None
        assert collector.error_metrics is not None
    
    def test_collect_all_metrics(self):
        """Test collecting all metrics."""
        collector = MetricsCollector()
        
        # Record some metrics
        collector.query_metrics.record_query(0.1, success=True)
        collector.cache_metrics.record_hit()
        
        all_metrics = collector.collect_all()
        assert "queries" in all_metrics
        assert "connection_pool" in all_metrics
        assert "cache" in all_metrics
        assert "errors" in all_metrics
    
    def test_export_prometheus(self):
        """Test exporting metrics in Prometheus format."""
        collector = MetricsCollector()
        
        # Record metrics
        collector.query_metrics.record_query(0.1, success=True)
        collector.cache_metrics.record_hit()
        
        prometheus_output = collector.export_prometheus()
        
        assert "mysql_queries_total" in prometheus_output
        assert "mysql_cache_hits_total" in prometheus_output
        assert "TYPE" in prometheus_output
        assert "HELP" in prometheus_output


class TestEnhancedJSONFormatter:
    """Test enhanced JSON log formatter."""
    
    def test_json_formatter(self):
        """Test JSON log formatting."""
        formatter = EnhancedJSONFormatter()
        
        # Create a real LogRecord
        import logging
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
            func="test_func"
        )
        
        # Format the record
        formatted = formatter.format(record)
        
        # Parse JSON
        log_data = json.loads(formatted)
        
        assert log_data["level"] == "INFO"
        assert log_data["message"] == "Test message"
        assert log_data["logger"] == "test_logger"
        assert log_data["location"]["file"] == "test.py"
        assert log_data["location"]["line"] == 42


class TestLogRotator:
    """Test log rotation functionality."""
    
    def test_log_rotator_creation(self):
        """Test creating log rotator."""
        rotator = LogRotator(
            filename="test.log",
            max_bytes=1024*1024,  # 1MB
            backup_count=3
        )
        
        assert rotator.filename == "test.log"
        assert rotator.max_bytes == 1024*1024
        assert rotator.backup_count == 3
    
    @patch('os.path.getsize')
    @patch('os.rename')
    def test_should_rotate(self, mock_rename, mock_getsize):
        """Test rotation logic."""
        rotator = LogRotator(
            filename="test.log",
            max_bytes=1000,
            backup_count=3
        )
        
        # File exceeds max size
        mock_getsize.return_value = 1500
        assert rotator.should_rotate() is True
        
        # File within size limit
        mock_getsize.return_value = 500
        assert rotator.should_rotate() is False