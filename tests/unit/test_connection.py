"""Unit tests for database connection management."""

import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Any

import pytest
import aiomysql
from aiomysql import OperationalError

from fastmcp_mysql.connection import (
    ConnectionManager,
    ConnectionConfig,
    ConnectionPoolError,
    create_connection_manager,
)


class TestConnectionConfig:
    """Test the ConnectionConfig class."""
    
    def test_default_values(self):
        """Test default values are set correctly."""
        config = ConnectionConfig(
            host="localhost",
            port=3306,
            user="testuser",
            password="testpass",
            database="testdb"
        )
        
        assert config.pool_size == 10
        assert config.charset == "utf8mb4"
        assert config.connect_timeout == 10
        assert config.autocommit is True
        assert config.echo is False
        assert config.ssl is None
    
    def test_custom_values(self):
        """Test custom values are set correctly."""
        config = ConnectionConfig(
            host="192.168.1.100",
            port=3307,
            user="myuser",
            password="mypass",
            database="mydb",
            pool_size=20,
            charset="utf8",
            connect_timeout=30,
            autocommit=False,
            echo=True
        )
        
        assert config.host == "192.168.1.100"
        assert config.port == 3307
        assert config.pool_size == 20
        assert config.charset == "utf8"
        assert config.connect_timeout == 30
        assert config.autocommit is False
        assert config.echo is True
    
    def test_from_settings(self):
        """Test creating config from Settings object."""
        mock_settings = Mock()
        mock_settings.host = "localhost"
        mock_settings.port = 3306
        mock_settings.user = "testuser"
        mock_settings.password = "testpass"
        mock_settings.db = "testdb"
        mock_settings.pool_size = 15
        mock_settings.query_timeout = 5000
        
        config = ConnectionConfig.from_settings(mock_settings)
        
        assert config.host == "localhost"
        assert config.port == 3306
        assert config.user == "testuser"
        assert config.password == "testpass"
        assert config.database == "testdb"
        assert config.pool_size == 15


class TestConnectionManager:
    """Test the ConnectionManager class."""
    
    @pytest.fixture
    def config(self):
        """Create a test configuration."""
        return ConnectionConfig(
            host="localhost",
            port=3306,
            user="testuser",
            password="testpass",
            database="testdb"
        )
    
    @pytest.fixture
    def manager(self, config):
        """Create a connection manager instance."""
        return ConnectionManager(config)
    
    @pytest.mark.asyncio
    async def test_create_pool_success(self, manager):
        """Test successful pool creation."""
        mock_pool = AsyncMock()
        
        with patch("aiomysql.create_pool", new_callable=AsyncMock) as mock_create:
            mock_create.return_value = mock_pool
            
            await manager.initialize()
            
            mock_create.assert_called_once()
            call_kwargs = mock_create.call_args.kwargs
            
            assert call_kwargs["host"] == "localhost"
            assert call_kwargs["port"] == 3306
            assert call_kwargs["user"] == "testuser"
            assert call_kwargs["password"] == "testpass"
            assert call_kwargs["db"] == "testdb"
            assert call_kwargs["minsize"] == 1
            assert call_kwargs["maxsize"] == 10
            assert call_kwargs["charset"] == "utf8mb4"
            assert call_kwargs["autocommit"] is True
            assert call_kwargs["connect_timeout"] == 10
    
    @pytest.mark.asyncio
    async def test_create_pool_retry_on_failure(self, manager):
        """Test pool creation with retry logic."""
        mock_pool = AsyncMock()
        
        with patch("aiomysql.create_pool", new_callable=AsyncMock) as mock_create:
            # First attempt fails, second succeeds
            mock_create.side_effect = [
                OperationalError("Connection failed"),
                mock_pool
            ]
            
            await manager.initialize()
            
            assert mock_create.call_count == 2
    
    @pytest.mark.asyncio
    async def test_create_pool_max_retries_exceeded(self, manager):
        """Test pool creation fails after max retries."""
        with patch("aiomysql.create_pool", new_callable=AsyncMock) as mock_create:
            mock_create.side_effect = OperationalError("Connection failed")
            
            with pytest.raises(ConnectionPoolError) as exc_info:
                await manager.initialize()
            
            assert "Failed to create connection pool after" in str(exc_info.value)
            assert mock_create.call_count == 3  # Default max retries
    
    @pytest.mark.asyncio
    async def test_get_connection_success(self, manager):
        """Test getting a connection from the pool."""
        mock_conn = AsyncMock()
        mock_acquire_cm = AsyncMock()
        mock_acquire_cm.__aenter__.return_value = mock_conn
        mock_acquire_cm.__aexit__.return_value = None
        
        mock_pool = Mock()
        mock_pool.acquire.return_value = mock_acquire_cm
        manager._pool = mock_pool
        
        async with manager.get_connection() as conn:
            assert conn == mock_conn
        
        mock_pool.acquire.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_connection_no_pool(self, manager):
        """Test getting connection when pool is not initialized."""
        with pytest.raises(ConnectionPoolError) as exc_info:
            async with manager.get_connection():
                pass
        
        assert "Connection pool not initialized" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_execute_query_success(self, manager):
        """Test executing a query successfully."""
        mock_cursor = AsyncMock()
        mock_cursor.fetchall.return_value = [{"id": 1, "name": "test"}]
        mock_cursor.description = [("id",), ("name",)]
        
        # cursor() returns an async context manager
        mock_conn = AsyncMock()
        mock_conn.cursor = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_cursor),
            __aexit__=AsyncMock(return_value=None)
        ))
        
        mock_acquire_cm = AsyncMock()
        mock_acquire_cm.__aenter__.return_value = mock_conn
        mock_acquire_cm.__aexit__.return_value = None
        
        mock_pool = Mock()
        mock_pool.acquire.return_value = mock_acquire_cm
        manager._pool = mock_pool
        
        result = await manager.execute("SELECT * FROM users WHERE id = %s", (1,))
        
        assert result == [{"id": 1, "name": "test"}]
        mock_cursor.execute.assert_called_once_with("SELECT * FROM users WHERE id = %s", (1,))
    
    @pytest.mark.asyncio
    async def test_execute_query_with_dict_cursor(self, manager):
        """Test executing a query with dict cursor."""
        mock_cursor = AsyncMock()
        mock_cursor.fetchall.return_value = [{"id": 1, "name": "test"}]
        mock_cursor.description = [("id",), ("name",)]
        
        # cursor() returns an async context manager
        mock_conn = AsyncMock()
        mock_conn.cursor = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_cursor),
            __aexit__=AsyncMock(return_value=None)
        ))
        
        mock_acquire_cm = AsyncMock()
        mock_acquire_cm.__aenter__.return_value = mock_conn
        mock_acquire_cm.__aexit__.return_value = None
        
        mock_pool = Mock()
        mock_pool.acquire.return_value = mock_acquire_cm
        manager._pool = mock_pool
        
        result = await manager.execute(
            "SELECT * FROM users", 
            cursor_class=aiomysql.DictCursor
        )
        
        mock_conn.cursor.assert_called_once_with(aiomysql.DictCursor)
    
    @pytest.mark.asyncio
    async def test_health_check_success(self, manager):
        """Test health check when connection is healthy."""
        mock_cursor = AsyncMock()
        mock_cursor.fetchone.return_value = (1,)
        
        # cursor() returns an async context manager
        mock_conn = AsyncMock()
        mock_conn.cursor = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_cursor),
            __aexit__=AsyncMock(return_value=None)
        ))
        
        mock_acquire_cm = AsyncMock()
        mock_acquire_cm.__aenter__.return_value = mock_conn
        mock_acquire_cm.__aexit__.return_value = None
        
        mock_pool = Mock()
        mock_pool.acquire.return_value = mock_acquire_cm
        manager._pool = mock_pool
        
        result = await manager.health_check()
        
        assert result is True
        mock_cursor.execute.assert_called_once_with("SELECT 1")
    
    @pytest.mark.asyncio
    async def test_health_check_failure(self, manager):
        """Test health check when connection fails."""
        mock_pool = Mock()
        mock_pool.acquire.side_effect = OperationalError("Connection lost")
        manager._pool = mock_pool
        
        result = await manager.health_check()
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_close_pool(self, manager):
        """Test closing the connection pool."""
        mock_pool = AsyncMock()
        mock_pool.close = Mock()
        mock_pool.wait_closed = AsyncMock()
        manager._pool = mock_pool
        
        await manager.close()
        
        mock_pool.close.assert_called_once()
        mock_pool.wait_closed.assert_called_once()
        assert manager._pool is None
    
    @pytest.mark.asyncio
    async def test_connection_metrics(self, manager):
        """Test connection pool metrics."""
        mock_pool = MagicMock()
        mock_pool.size = 10
        mock_pool.freesize = 7
        mock_pool.minsize = 1
        mock_pool.maxsize = 10
        manager._pool = mock_pool
        
        metrics = manager.get_pool_metrics()
        
        assert metrics["total_connections"] == 10
        assert metrics["free_connections"] == 7
        assert metrics["used_connections"] == 3
        assert metrics["min_size"] == 1
        assert metrics["max_size"] == 10


class TestCreateConnectionManager:
    """Test the factory function."""
    
    @pytest.mark.asyncio
    async def test_create_from_settings(self):
        """Test creating connection manager from settings."""
        mock_settings = Mock()
        mock_settings.host = "localhost"
        mock_settings.port = 3306
        mock_settings.user = "testuser"
        mock_settings.password = "testpass"
        mock_settings.db = "testdb"
        mock_settings.pool_size = 5
        mock_settings.query_timeout = 30000
        
        with patch("aiomysql.create_pool", new_callable=AsyncMock) as mock_create:
            mock_pool = AsyncMock()
            mock_create.return_value = mock_pool
            
            manager = await create_connection_manager(mock_settings)
            
            assert isinstance(manager, ConnectionManager)
            assert manager._pool == mock_pool


class TestConnectionRetry:
    """Test connection retry logic."""
    
    @pytest.mark.asyncio
    async def test_exponential_backoff(self):
        """Test exponential backoff in retry logic."""
        config = ConnectionConfig(
            host="localhost",
            port=3306,
            user="testuser",
            password="testpass",
            database="testdb"
        )
        manager = ConnectionManager(config)
        
        with patch("aiomysql.create_pool", new_callable=AsyncMock) as mock_create:
            mock_create.side_effect = OperationalError("Connection failed")
            
            with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                try:
                    await manager.initialize()
                except ConnectionPoolError:
                    pass
                
                # Check exponential backoff delays
                expected_delays = [1, 2]  # 1s, 2s for retries
                actual_delays = [call.args[0] for call in mock_sleep.call_args_list]
                assert actual_delays == expected_delays