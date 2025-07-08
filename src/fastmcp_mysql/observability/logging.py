"""Enhanced logging system for FastMCP MySQL server."""

import json
import logging
import logging.handlers
import os
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, List, Union
from uuid import uuid4

from ..config import LogLevel


@dataclass
class RequestContext:
    """Context information for a request."""
    request_id: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, omitting None values."""
        return {k: v for k, v in asdict(self).items() if v is not None}


class EnhancedJSONFormatter(logging.Formatter):
    """Enhanced JSON formatter with context and metrics support."""
    
    def __init__(self, include_hostname: bool = True, include_process_info: bool = True):
        """Initialize enhanced formatter.
        
        Args:
            include_hostname: Whether to include hostname in logs
            include_process_info: Whether to include process/thread info
        """
        super().__init__()
        self.include_hostname = include_hostname
        self.include_process_info = include_process_info
        self.hostname = os.uname().nodename if include_hostname else None
        self.pid = os.getpid() if include_process_info else None
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as enhanced JSON."""
        # Base log data
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add location info
        log_data["location"] = {
            "file": record.pathname,
            "line": record.lineno,
            "function": record.funcName,
        }
        
        # Add system info
        if self.include_hostname:
            log_data["hostname"] = self.hostname
        
        if self.include_process_info:
            log_data["process"] = {
                "pid": self.pid,
                "thread_id": threading.get_ident(),
                "thread_name": threading.current_thread().name,
            }
        
        # Add context from thread-local storage
        context = getattr(threading.current_thread(), 'request_context', None)
        if context and isinstance(context, RequestContext):
            log_data["context"] = context.to_dict()
        
        # Add extra fields
        if hasattr(record, "__dict__"):
            for key, value in record.__dict__.items():
                if key not in ["name", "msg", "args", "created", "filename", "funcName",
                              "levelname", "levelno", "lineno", "module", "msecs",
                              "pathname", "process", "processName", "relativeCreated",
                              "thread", "threadName", "exc_info", "exc_text", "stack_info"]:
                    # Serialize complex objects
                    try:
                        if hasattr(value, "to_dict"):
                            log_data[key] = value.to_dict()
                        elif isinstance(value, (dict, list, str, int, float, bool, type(None))):
                            log_data[key] = value
                        else:
                            log_data[key] = str(value)
                    except Exception:
                        log_data[key] = repr(value)
        
        # Add exception info
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": self.formatException(record.exc_info),
            }
        
        return json.dumps(log_data, default=str)


class ContextLogger:
    """Logger wrapper that automatically includes context information."""
    
    def __init__(self, logger: logging.Logger):
        """Initialize context logger.
        
        Args:
            logger: Underlying logger instance
        """
        self.logger = logger
    
    def _log(self, level: int, msg: str, *args, **kwargs):
        """Log with context information."""
        # Get context from thread-local storage
        context = getattr(threading.current_thread(), 'request_context', None)
        
        # Merge context into extra
        extra = kwargs.get('extra', {})
        if context and isinstance(context, RequestContext):
            extra['request_id'] = context.request_id
            extra['user_id'] = context.user_id
            extra['session_id'] = context.session_id
        
        kwargs['extra'] = extra
        self.logger.log(level, msg, *args, **kwargs)
    
    def debug(self, msg: str, *args, **kwargs):
        """Log debug message."""
        self._log(logging.DEBUG, msg, *args, **kwargs)
    
    def info(self, msg: str, *args, **kwargs):
        """Log info message."""
        self._log(logging.INFO, msg, *args, **kwargs)
    
    def warning(self, msg: str, *args, **kwargs):
        """Log warning message."""
        self._log(logging.WARNING, msg, *args, **kwargs)
    
    def error(self, msg: str, *args, **kwargs):
        """Log error message."""
        self._log(logging.ERROR, msg, *args, **kwargs)
    
    def critical(self, msg: str, *args, **kwargs):
        """Log critical message."""
        self._log(logging.CRITICAL, msg, *args, **kwargs)


class MetricsLogger:
    """Logger for metrics and performance data."""
    
    def __init__(self, logger: logging.Logger):
        """Initialize metrics logger.
        
        Args:
            logger: Underlying logger instance
        """
        self.logger = logger
    
    def log_query_metrics(self, query: str, duration_ms: float, rows_affected: int,
                         success: bool, error: Optional[str] = None):
        """Log query execution metrics."""
        self.logger.info(
            "query_executed",
            extra={
                "metrics": {
                    "type": "query",
                    "query": query[:100],  # Truncate long queries
                    "duration_ms": duration_ms,
                    "rows_affected": rows_affected,
                    "success": success,
                    "error": error,
                }
            }
        )
    
    def log_connection_metrics(self, total: int, free: int, used: int):
        """Log connection pool metrics."""
        self.logger.info(
            "connection_pool_status",
            extra={
                "metrics": {
                    "type": "connection_pool",
                    "total_connections": total,
                    "free_connections": free,
                    "used_connections": used,
                    "utilization": (used / total * 100) if total > 0 else 0,
                }
            }
        )
    
    def log_cache_metrics(self, hits: int, misses: int, evictions: int, size: int):
        """Log cache performance metrics."""
        hit_rate = (hits / (hits + misses) * 100) if (hits + misses) > 0 else 0
        self.logger.info(
            "cache_performance",
            extra={
                "metrics": {
                    "type": "cache",
                    "hits": hits,
                    "misses": misses,
                    "evictions": evictions,
                    "size": size,
                    "hit_rate": hit_rate,
                }
            }
        )
    
    def log_error_metrics(self, error_type: str, count: int, rate: float):
        """Log error metrics."""
        self.logger.warning(
            "error_rate",
            extra={
                "metrics": {
                    "type": "error",
                    "error_type": error_type,
                    "count": count,
                    "rate_per_minute": rate,
                }
            }
        )


def setup_rotating_file_handler(log_dir: Path, max_bytes: int = 100 * 1024 * 1024,
                               backup_count: int = 10) -> logging.Handler:
    """Set up rotating file handler.
    
    Args:
        log_dir: Directory for log files
        max_bytes: Maximum size per log file
        backup_count: Number of backup files to keep
        
    Returns:
        Configured rotating file handler
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Create separate handlers for different log levels
    handlers = []
    
    # All logs
    all_handler = logging.handlers.RotatingFileHandler(
        log_dir / "fastmcp-mysql.log",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    all_handler.setFormatter(EnhancedJSONFormatter())
    handlers.append(all_handler)
    
    # Error logs only
    error_handler = logging.handlers.RotatingFileHandler(
        log_dir / "fastmcp-mysql-errors.log",
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(EnhancedJSONFormatter())
    handlers.append(error_handler)
    
    return handlers


@contextmanager
def request_context(request_id: Optional[str] = None, **kwargs):
    """Context manager for request-scoped logging context.
    
    Args:
        request_id: Request ID (generated if not provided)
        **kwargs: Additional context fields
        
    Example:
        with request_context(user_id="user123"):
            logger.info("Processing request")
    """
    if request_id is None:
        request_id = str(uuid4())
    
    context = RequestContext(request_id=request_id, **kwargs)
    
    # Store in thread-local storage
    thread = threading.current_thread()
    old_context = getattr(thread, 'request_context', None)
    thread.request_context = context
    
    try:
        yield context
    finally:
        # Restore old context
        if old_context:
            thread.request_context = old_context
        else:
            delattr(thread, 'request_context')


def setup_enhanced_logging(log_level: LogLevel = LogLevel.INFO,
                          log_dir: Optional[Path] = None,
                          enable_file_logging: bool = True,
                          enable_console_logging: bool = True) -> None:
    """Set up enhanced logging system.
    
    Args:
        log_level: Logging level
        log_dir: Directory for log files (if file logging enabled)
        enable_file_logging: Whether to enable file logging
        enable_console_logging: Whether to enable console logging
    """
    # Convert log level
    level_map = {
        LogLevel.DEBUG: logging.DEBUG,
        LogLevel.INFO: logging.INFO,
        LogLevel.WARNING: logging.WARNING,
        LogLevel.ERROR: logging.ERROR,
        LogLevel.CRITICAL: logging.CRITICAL,
    }
    
    # Configure handlers
    handlers = []
    
    if enable_console_logging:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(EnhancedJSONFormatter())
        handlers.append(console_handler)
    
    if enable_file_logging and log_dir:
        file_handlers = setup_rotating_file_handler(log_dir)
        handlers.extend(file_handlers)
    
    # Configure root logger
    logging.basicConfig(
        level=level_map.get(log_level, logging.INFO),
        handlers=handlers,
        force=True  # Force reconfiguration
    )
    
    # Set specific loggers
    for logger_name in ["fastmcp", "fastmcp_mysql"]:
        logger = logging.getLogger(logger_name)
        logger.setLevel(level_map.get(log_level, logging.INFO))
        logger.propagate = False
        for handler in handlers:
            logger.addHandler(handler)
    
    # Log configuration
    logger = logging.getLogger(__name__)
    logger.info(
        "Enhanced logging system initialized",
        extra={
            "config": {
                "log_level": log_level.value,
                "file_logging": enable_file_logging,
                "console_logging": enable_console_logging,
                "log_dir": str(log_dir) if log_dir else None,
            }
        }
    )