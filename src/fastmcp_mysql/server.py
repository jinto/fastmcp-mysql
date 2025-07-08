"""FastMCP server implementation for MySQL."""

import logging
import json
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from fastmcp import FastMCP, Context

from .config import Settings, LogLevel
from .connection import create_connection_manager, ConnectionManager
from .tools.query import set_connection_manager


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