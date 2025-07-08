"""FastMCP server implementation for MySQL."""

import logging
import json
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from fastmcp import FastMCP, Context

from .config import Settings, LogLevel
from .connection import create_connection_manager, ConnectionManager
from .tools.query import set_connection_manager, set_security_manager
from .security import SecurityManager, SecuritySettings
from .security.config import FilterMode, RateLimitAlgorithm
from .security.injection import SQLInjectionDetector
from .security.filtering import BlacklistFilter, WhitelistFilter
from .security.rate_limiting import create_rate_limiter


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
        }
        
        # Add extra fields if present
        if hasattr(record, "extra"):
            for key, value in record.extra.items():
                if key not in ["message", "asctime"]:
                    log_data[key] = value
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_data)


def setup_logging() -> None:
    """Configure structured logging."""
    # Get log level from environment
    try:
        settings = Settings(_env_file=None)
        log_level = settings.log_level
    except Exception:
        # Default to INFO if settings can't be loaded
        log_level = LogLevel.INFO
    
    # Convert string level to logging constant
    level_map = {
        LogLevel.DEBUG: logging.DEBUG,
        LogLevel.INFO: logging.INFO,
        LogLevel.WARNING: logging.WARNING,
        LogLevel.ERROR: logging.ERROR,
        LogLevel.CRITICAL: logging.CRITICAL,
    }
    
    # Create JSON handler
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    
    # Configure root logger
    logging.basicConfig(
        level=level_map.get(log_level, logging.INFO),
        handlers=[handler]
    )
    
    # Set specific loggers
    logging.getLogger("fastmcp").setLevel(level_map.get(log_level, logging.INFO))
    logging.getLogger("fastmcp_mysql").setLevel(level_map.get(log_level, logging.INFO))


def setup_security(settings: Settings) -> Optional[SecurityManager]:
    """Set up security manager if enabled.
    
    Args:
        settings: Application settings
        
    Returns:
        SecurityManager: Initialized security manager or None if disabled
    """
    logger = logging.getLogger(__name__)
    
    # Check if security is enabled
    if not getattr(settings, 'enable_security', True):
        logger.info("Security features disabled")
        return None
    
    try:
        # Create security settings from environment
        security_settings = SecuritySettings(
            enable_injection_detection=getattr(settings, 'enable_injection_detection', True),
            enable_rate_limiting=getattr(settings, 'enable_rate_limiting', True),
            filter_mode=getattr(settings, 'filter_mode', FilterMode.BLACKLIST),
            rate_limit_requests_per_minute=getattr(settings, 'rate_limit_rpm', 60),
            rate_limit_burst_size=getattr(settings, 'rate_limit_burst', 10),
        )
        
        # Create components
        injection_detector = SQLInjectionDetector() if security_settings.enable_injection_detection else None
        
        # Create filter based on mode
        query_filter = None
        if security_settings.filter_mode == FilterMode.BLACKLIST:
            query_filter = BlacklistFilter(security_settings)
        elif security_settings.filter_mode == FilterMode.WHITELIST:
            # Would need whitelist patterns from config
            logger.warning("Whitelist mode configured but no patterns provided")
        
        # Create rate limiter
        rate_limiter = None
        if security_settings.enable_rate_limiting:
            rate_limiter = create_rate_limiter(
                algorithm=security_settings.rate_limit_algorithm,
                requests_per_minute=security_settings.rate_limit_requests_per_minute,
                burst_size=security_settings.rate_limit_burst_size
            )
        
        # Create security manager
        manager = SecurityManager(
            settings=security_settings,
            injection_detector=injection_detector,
            query_filter=query_filter,
            rate_limiter=rate_limiter
        )
        
        # Set global security manager
        set_security_manager(manager)
        
        logger.info(
            "Security manager initialized",
            extra={
                "injection_detection": security_settings.enable_injection_detection,
                "rate_limiting": security_settings.enable_rate_limiting,
                "filter_mode": security_settings.filter_mode.value
            }
        )
        
        return manager
        
    except Exception as e:
        logger.error(f"Failed to initialize security manager: {e}")
        # Security is optional, so we don't raise
        return None


async def setup_connection(settings: Settings) -> ConnectionManager:
    """Set up database connection.
    
    Args:
        settings: Application settings
        
    Returns:
        ConnectionManager: Initialized connection manager
    """
    logger = logging.getLogger(__name__)
    
    try:
        # Create and initialize connection manager
        manager = await create_connection_manager(settings)
        
        # Set global connection manager for tools
        set_connection_manager(manager)
        
        logger.info("Database connection established")
        return manager
        
    except Exception as e:
        logger.error(f"Failed to establish database connection: {e}")
        raise


def create_server() -> FastMCP:
    """Create and configure the FastMCP server.
    
    Returns:
        FastMCP: Configured FastMCP server instance
        
    Raises:
        ValidationError: If required configuration is missing
    """
    # Load and validate settings
    settings = Settings()
    
    # Create server
    mcp = FastMCP("MySQL Server")
    
    # Store settings in server for later use
    mcp._settings = settings  # type: ignore
    
    # Initialize security if enabled
    setup_security(settings)
    
    # Log server creation
    logger = logging.getLogger(__name__)
    logger.info(
        "FastMCP MySQL server created",
        extra={
            "host": settings.host,
            "port": settings.port,
            "database": settings.db,
            "user": settings.user,
            "allow_write": any([
                settings.allow_insert,
                settings.allow_update,
                settings.allow_delete
            ])
        }
    )
    
    # Initialize connection on first use
    _connection_initialized = False
    
    async def ensure_connection():
        """Ensure database connection is initialized."""
        nonlocal _connection_initialized
        if not _connection_initialized:
            await setup_connection(settings)
            _connection_initialized = True
    
    # Register the mysql_query tool
    @mcp.tool
    async def mysql_query(
        query: str,
        params: Optional[List[Any]] = None,
        database: Optional[str] = None,
        context: Optional[Context] = None
    ) -> Dict[str, Any]:
        """Execute a MySQL query.
        
        Args:
            query: SQL query to execute
            params: Optional query parameters for prepared statements
            database: Optional database name for multi-database mode
            context: FastMCP context
            
        Returns:
            Dictionary containing query results or error information
        """
        # Ensure connection is initialized
        await ensure_connection()
        
        from .tools.query import mysql_query as _mysql_query
        return await _mysql_query(query, params, database, context)
    
    return mcp