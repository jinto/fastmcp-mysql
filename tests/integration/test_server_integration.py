"""Integration tests for FastMCP MySQL server."""

import os
from unittest.mock import patch, AsyncMock, Mock, MagicMock

import pytest
from fastmcp import FastMCP

from fastmcp_mysql.server import create_server, setup_connection
from fastmcp_mysql.config import Settings


class TestServerIntegration:
    """Test server integration."""
    
    def test_create_server(self):
        """Test server creation."""
        with patch.dict(os.environ, {
            "MYSQL_HOST": "localhost",
            "MYSQL_PORT": "3306",
            "MYSQL_USER": "testuser",
            "MYSQL_PASSWORD": "testpass",
            "MYSQL_DB": "testdb"
        }):
            server = create_server()
            
            assert isinstance(server, FastMCP)
            assert hasattr(server, "_settings")
            assert server._settings.host == "localhost"
            assert server._settings.user == "testuser"
            assert server._settings.db == "testdb"
    
    @pytest.mark.asyncio
    async def test_server_has_mysql_query_tool(self):
        """Test that server has mysql_query tool registered."""
        with patch.dict(os.environ, {
            "MYSQL_HOST": "localhost",
            "MYSQL_PORT": "3306",
            "MYSQL_USER": "testuser",
            "MYSQL_PASSWORD": "testpass",
            "MYSQL_DB": "testdb"
        }):
            server = create_server()
            
            # Check that mysql_query tool is registered
            tools = await server.get_tools()
            assert isinstance(tools, dict)
            assert "mysql_query" in tools
    
    @pytest.mark.asyncio
    async def test_setup_connection_success(self):
        """Test successful database connection setup."""
        settings = Settings(
            host="localhost",
            port=3306,
            user="testuser",
            password="testpass",
            db="testdb"
        )
        
        with patch("fastmcp_mysql.server.create_connection_manager") as mock_create:
            mock_manager = AsyncMock()
            mock_create.return_value = mock_manager
            
            with patch("fastmcp_mysql.server.set_connection_manager") as mock_set:
                result = await setup_connection(settings)
                
                assert result == mock_manager
                mock_create.assert_called_once_with(settings)
                mock_set.assert_called_once_with(mock_manager)
    
    @pytest.mark.asyncio
    async def test_setup_connection_failure(self):
        """Test database connection setup failure."""
        settings = Settings(
            host="localhost",
            port=3306,
            user="testuser",
            password="testpass",
            db="testdb"
        )
        
        with patch("fastmcp_mysql.server.create_connection_manager") as mock_create:
            mock_create.side_effect = Exception("Connection failed")
            
            with pytest.raises(Exception, match="Connection failed"):
                await setup_connection(settings)
    
    @pytest.mark.asyncio
    async def test_server_has_tools(self):
        """Test that server has required tools."""
        with patch.dict(os.environ, {
            "MYSQL_HOST": "localhost",
            "MYSQL_PORT": "3306",
            "MYSQL_USER": "testuser",
            "MYSQL_PASSWORD": "testpass",
            "MYSQL_DB": "testdb"
        }):
            server = create_server()
            
            # Check that tools are available
            tools = await server.get_tools()
            assert len(tools) > 0
            assert "mysql_query" in tools
            
            # Get the tool info
            mysql_query_tool = tools["mysql_query"]
            assert mysql_query_tool is not None
            assert mysql_query_tool.name == "mysql_query"
    
    @pytest.mark.asyncio
    async def test_mysql_query_tool_execution(self):
        """Test mysql_query tool execution."""
        # Import the mysql_query function directly
        from fastmcp_mysql.tools.query import mysql_query
        
        # Mock the connection manager
        mock_manager = AsyncMock()
        mock_manager.execute.return_value = [
            {"id": 1, "name": "Test User"}
        ]
        
        with patch("fastmcp_mysql.tools.query.get_connection_manager") as mock_get:
            mock_get.return_value = mock_manager
            
            # Execute the tool function
            result = await mysql_query(
                query="SELECT * FROM users WHERE id = %s",
                params=[1]
            )
            
            assert result["success"] is True
            assert result["data"] == [{"id": 1, "name": "Test User"}]
            assert result["message"] == "Query executed successfully"
    
    def test_server_with_write_permissions(self):
        """Test server creation with write permissions enabled."""
        with patch.dict(os.environ, {
            "MYSQL_HOST": "localhost",
            "MYSQL_PORT": "3306",
            "MYSQL_USER": "testuser",
            "MYSQL_PASSWORD": "testpass",
            "MYSQL_DB": "testdb",
            "MYSQL_ALLOW_INSERT": "true",
            "MYSQL_ALLOW_UPDATE": "true",
            "MYSQL_ALLOW_DELETE": "false"
        }):
            server = create_server()
            
            assert server._settings.allow_insert is True
            assert server._settings.allow_update is True
            assert server._settings.allow_delete is False
    
    def test_server_with_custom_settings(self):
        """Test server creation with custom settings."""
        with patch.dict(os.environ, {
            "MYSQL_HOST": "192.168.1.100",
            "MYSQL_PORT": "3307",
            "MYSQL_USER": "admin",
            "MYSQL_PASSWORD": "secret",
            "MYSQL_DB": "production",
            "MYSQL_POOL_SIZE": "20",
            "MYSQL_QUERY_TIMEOUT": "60000",
            "MYSQL_LOG_LEVEL": "DEBUG"
        }):
            server = create_server()
            
            settings = server._settings
            assert settings.host == "192.168.1.100"
            assert settings.port == 3307
            assert settings.user == "admin"
            assert settings.db == "production"
            assert settings.pool_size == 20
            assert settings.query_timeout == 60000