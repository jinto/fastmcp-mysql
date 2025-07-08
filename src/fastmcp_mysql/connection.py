"""Database connection management for FastMCP MySQL server."""

import asyncio
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Type, AsyncIterator, List, Tuple

import aiomysql
from aiomysql import DictCursor, Pool, Connection, OperationalError, SSCursor, SSDictCursor

from .config import Settings

logger = logging.getLogger(__name__)


class ConnectionPoolError(Exception):
    """Raised when connection pool operations fail."""
    pass


@dataclass
class SSLConfig:
    """SSL configuration for MySQL connections."""
    ca: Optional[str] = None
    cert: Optional[str] = None
    key: Optional[str] = None
    verify_cert: bool = True
    verify_identity: bool = True


@dataclass
class ConnectionConfig:
    """Configuration for MySQL connections."""
    host: str
    port: int
    user: str
    password: str
    database: str
    pool_size: int = 10
    charset: str = "utf8mb4"
    connect_timeout: int = 10
    autocommit: bool = True
    echo: bool = False
    ssl: Optional[SSLConfig] = None
    
    @classmethod
    def from_settings(cls, settings: Settings) -> "ConnectionConfig":
        """Create configuration from settings object."""
        return cls(
            host=settings.host,
            port=settings.port,
            user=settings.user,
            password=settings.password,
            database=settings.db,
            pool_size=settings.pool_size,
            connect_timeout=settings.query_timeout // 1000,  # Convert ms to seconds
        )


class ConnectionManager:
    """Manages MySQL connection pool and database operations."""
    
    def __init__(self, config: ConnectionConfig):
        """Initialize connection manager.
        
        Args:
            config: Connection configuration
        """
        self.config = config
        self._pool: Optional[Pool] = None
        self._retry_count = 3
        self._retry_delay = 1
    
    async def initialize(self) -> None:
        """Initialize the connection pool with retry logic."""
        last_error = None
        
        for attempt in range(self._retry_count):
            try:
                await self._create_pool()
                logger.info(
                    "Connection pool created successfully",
                    extra={
                        "host": self.config.host,
                        "port": self.config.port,
                        "database": self.config.database,
                        "pool_size": self.config.pool_size,
                    }
                )
                return
            except Exception as e:
                last_error = e
                logger.warning(
                    f"Failed to create connection pool (attempt {attempt + 1}/{self._retry_count})",
                    extra={"error": str(e)}
                )
                
                if attempt < self._retry_count - 1:
                    delay = self._retry_delay * (2 ** attempt)  # Exponential backoff
                    await asyncio.sleep(delay)
        
        raise ConnectionPoolError(
            f"Failed to create connection pool after {self._retry_count} attempts: {last_error}"
        )
    
    async def _create_pool(self) -> None:
        """Create the aiomysql connection pool."""
        pool_kwargs = {
            "host": self.config.host,
            "port": self.config.port,
            "user": self.config.user,
            "password": self.config.password,
            "db": self.config.database,
            "minsize": 1,
            "maxsize": self.config.pool_size,
            "charset": self.config.charset,
            "autocommit": self.config.autocommit,
            "connect_timeout": self.config.connect_timeout,
            "echo": self.config.echo,
        }
        
        # Add SSL configuration if provided
        if self.config.ssl:
            ssl_ctx = {
                "ca": self.config.ssl.ca,
                "cert": self.config.ssl.cert,
                "key": self.config.ssl.key,
                "verify_cert": self.config.ssl.verify_cert,
                "verify_identity": self.config.ssl.verify_identity,
            }
            # Remove None values
            ssl_ctx = {k: v for k, v in ssl_ctx.items() if v is not None}
            if ssl_ctx:
                pool_kwargs["ssl"] = ssl_ctx
        
        self._pool = await aiomysql.create_pool(**pool_kwargs)
    
    @asynccontextmanager
    async def get_connection(self) -> AsyncIterator[Connection]:
        """Get a connection from the pool.
        
        Yields:
            Connection object
            
        Raises:
            ConnectionPoolError: If pool is not initialized
        """
        if not self._pool:
            raise ConnectionPoolError("Connection pool not initialized")
        
        async with self._pool.acquire() as conn:
            yield conn
    
    async def execute(
        self,
        query: str,
        params: Optional[tuple] = None,
        cursor_class: Type[Any] = DictCursor
    ) -> Any:
        """Execute a query and return results.
        
        Args:
            query: SQL query to execute
            params: Query parameters
            cursor_class: Cursor class to use (default: DictCursor)
            
        Returns:
            Query results
            
        Raises:
            ConnectionPoolError: If pool is not initialized
        """
        async with self.get_connection() as conn:
            async with conn.cursor(cursor_class) as cursor:
                await cursor.execute(query, params)
                
                # Check if this is a SELECT query
                if cursor.description:
                    return await cursor.fetchall()
                else:
                    # For INSERT/UPDATE/DELETE, return affected rows
                    return cursor.rowcount
    
    async def execute_streaming(
        self,
        query: str,
        params: Optional[tuple] = None,
        chunk_size: int = 1000,
        cursor_class: Type[Any] = SSDictCursor
    ) -> AsyncIterator[List[Dict[str, Any]]]:
        """Execute a query and stream results in chunks.
        
        This method is memory-efficient for large result sets as it doesn't
        load all results into memory at once.
        
        Args:
            query: SQL query to execute
            params: Query parameters
            chunk_size: Number of rows to fetch per chunk
            cursor_class: Cursor class to use (default: SSDictCursor for streaming)
            
        Yields:
            Chunks of query results
            
        Raises:
            ConnectionPoolError: If pool is not initialized
        """
        async with self.get_connection() as conn:
            # Use server-side cursor for streaming
            async with conn.cursor(cursor_class) as cursor:
                await cursor.execute(query, params)
                
                # Check if this is a SELECT query
                if not cursor.description:
                    return  # No results to stream
                
                while True:
                    chunk = await cursor.fetchmany(chunk_size)
                    if not chunk:
                        break
                    yield chunk
    
    async def execute_paginated(
        self,
        query: str,
        params: Optional[tuple] = None,
        page: int = 1,
        page_size: int = 10,
        max_page_size: int = 1000,
        cursor_class: Type[Any] = DictCursor
    ) -> Dict[str, Any]:
        """Execute a query with pagination support.
        
        Args:
            query: SQL query to execute
            params: Query parameters
            page: Page number (1-based)
            page_size: Number of rows per page
            max_page_size: Maximum allowed page size
            cursor_class: Cursor class to use (default: DictCursor)
            
        Returns:
            Dictionary with 'data' and 'pagination' keys
            
        Raises:
            ConnectionPoolError: If pool is not initialized
        """
        # Validate and adjust parameters
        page = max(1, page)  # Ensure page is at least 1
        page_size = min(max(1, page_size), max_page_size)  # Limit page size
        
        # First, get the total count
        count_query = f"SELECT COUNT(*) as total FROM ({query}) as subquery"
        
        async with self.get_connection() as conn:
            async with conn.cursor(cursor_class) as cursor:
                await cursor.execute(count_query, params)
                count_result = await cursor.fetchone()
                
                if cursor_class == DictCursor:
                    total_count = count_result["total"]
                else:
                    total_count = count_result[0]
                
                # Calculate pagination info
                total_pages = (total_count + page_size - 1) // page_size if total_count > 0 else 0
                
                # Adjust page if beyond total pages
                if page > total_pages and total_pages > 0:
                    page = total_pages
                
                # Calculate offset
                offset = (page - 1) * page_size
                
                # Execute paginated query
                paginated_query = f"{query} LIMIT {page_size} OFFSET {offset}"
                await cursor.execute(paginated_query, params)
                data = await cursor.fetchall()
        
        return {
            "data": data,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_count": total_count,
                "total_pages": total_pages,
                "has_next": page < total_pages,
                "has_previous": page > 1
            }
        }
    
    async def health_check(self) -> bool:
        """Check if the database connection is healthy.
        
        Returns:
            True if healthy, False otherwise
        """
        if not self._pool:
            return False
        
        try:
            async with self.get_connection() as conn:
                async with conn.cursor() as cursor:
                    await cursor.execute("SELECT 1")
                    result = await cursor.fetchone()
                    return result == (1,)
        except Exception as e:
            logger.warning(f"Health check failed: {e}")
            return False
    
    def get_pool_metrics(self) -> Dict[str, int]:
        """Get connection pool metrics.
        
        Returns:
            Dictionary with pool metrics
        """
        if not self._pool:
            return {
                "total_connections": 0,
                "free_connections": 0,
                "used_connections": 0,
                "min_size": 0,
                "max_size": 0,
            }
        
        return {
            "total_connections": self._pool.size,
            "free_connections": self._pool.freesize,
            "used_connections": self._pool.size - self._pool.freesize,
            "min_size": self._pool.minsize,
            "max_size": self._pool.maxsize,
        }
    
    async def close(self) -> None:
        """Close the connection pool."""
        if self._pool:
            self._pool.close()
            await self._pool.wait_closed()
            self._pool = None
            logger.info("Connection pool closed")


async def create_connection_manager(settings: Settings) -> ConnectionManager:
    """Create and initialize a connection manager from settings.
    
    Args:
        settings: Application settings
        
    Returns:
        Initialized ConnectionManager
    """
    config = ConnectionConfig.from_settings(settings)
    manager = ConnectionManager(config)
    await manager.initialize()
    return manager