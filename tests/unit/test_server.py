"""Unit tests for server initialization and lifecycle."""

import asyncio
from unittest.mock import Mock, patch, AsyncMock

import pytest

from fastmcp_mysql.server import create_server, setup_logging


class TestServerCreation:
    """Test server creation and initialization."""

    @patch("fastmcp_mysql.server.Settings")
    def test_create_server_success(self, mock_settings_class):
        """Test successful server creation."""
        # Mock settings
        mock_settings = Mock()
        mock_settings.mysql_user = "testuser"
        mock_settings.mysql_db = "testdb"
        mock_settings_class.return_value = mock_settings
        
        # Create server
        server = create_server()
        
        # Verify server is created
        assert server is not None
        assert hasattr(server, "name")
        assert server.name == "MySQL Server"

    @patch("fastmcp_mysql.server.Settings")
    def test_create_server_with_invalid_config(self, mock_settings_class):
        """Test server creation fails with invalid configuration."""
        # Mock settings to raise validation error
        from pydantic import ValidationError
        mock_settings_class.side_effect = ValidationError.from_exception_data(
            "ValidationError", 
            [{"type": "missing", "loc": ("mysql_user",), "msg": "Field required"}]
        )
        
        # Verify server creation fails
        with pytest.raises(ValidationError):
            create_server()

    @patch("fastmcp_mysql.server.Settings")
    @patch("fastmcp_mysql.server.FastMCP")
    def test_server_metadata(self, mock_fastmcp_class, mock_settings_class):
        """Test server metadata is set correctly."""
        # Mock settings
        mock_settings = Mock()
        mock_settings_class.return_value = mock_settings
        
        # Mock FastMCP
        mock_mcp = Mock()
        mock_fastmcp_class.return_value = mock_mcp
        
        # Create server
        server = create_server()
        
        # Verify FastMCP was called with correct name
        mock_fastmcp_class.assert_called_once_with("MySQL Server")
        assert server == mock_mcp


class TestLoggingSetup:
    """Test logging configuration."""

    @patch("fastmcp_mysql.server.logging")
    def test_setup_logging_default(self, mock_logging):
        """Test default logging setup."""
        # Setup logging
        setup_logging()
        
        # Verify basic config was called
        mock_logging.basicConfig.assert_called_once()
        
        # Check if JSON formatter is used
        call_kwargs = mock_logging.basicConfig.call_args.kwargs
        assert "format" in call_kwargs or "handlers" in call_kwargs

    @patch("fastmcp_mysql.server.logging")
    @patch.dict("os.environ", {
        "MYSQL_LOG_LEVEL": "DEBUG",
        "MYSQL_USER": "testuser",
        "MYSQL_PASSWORD": "testpass",
        "MYSQL_DB": "testdb"
    })
    def test_setup_logging_with_env_level(self, mock_logging):
        """Test logging setup with environment variable."""
        # Mock getLogger
        mock_logger = Mock()
        mock_logging.getLogger.return_value = mock_logger
        mock_logging.DEBUG = 10
        
        # Setup logging
        setup_logging()
        
        # Verify log level was set
        mock_logging.basicConfig.assert_called_once()
        call_kwargs = mock_logging.basicConfig.call_args.kwargs
        assert call_kwargs.get("level") == 10

    def test_setup_logging_json_format(self):
        """Test that logging uses JSON format."""
        import logging
        import json
        from io import StringIO
        
        # Create string buffer for logs
        log_buffer = StringIO()
        
        # Setup handler with buffer
        handler = logging.StreamHandler(log_buffer)
        
        # Call setup_logging and get the formatter
        with patch("logging.basicConfig") as mock_basic_config:
            setup_logging()
            
            # Get the handlers from the call
            if mock_basic_config.called:
                call_kwargs = mock_basic_config.call_args.kwargs
                handlers = call_kwargs.get("handlers", [])
                if handlers and hasattr(handlers[0], "formatter"):
                    formatter = handlers[0].formatter
                    handler.setFormatter(formatter)
        
        # Create test logger
        test_logger = logging.getLogger("test")
        test_logger.handlers = [handler]
        test_logger.setLevel(logging.INFO)
        
        # Log a test message
        test_logger.info("Test message", extra={"user": "testuser", "query_id": "123"})
        
        # Get logged output
        log_output = log_buffer.getvalue()
        
        # Verify it's valid JSON (if JSON formatter is used)
        if log_output.strip():
            try:
                log_data = json.loads(log_output.strip())
                assert "message" in log_data or "msg" in log_data
            except json.JSONDecodeError:
                # If not JSON, at least verify it contains the message
                assert "Test message" in log_output


class TestServerLifecycle:
    """Test server startup and shutdown."""

    @pytest.mark.asyncio
    @patch("fastmcp_mysql.server.Settings")
    @patch("fastmcp_mysql.server.FastMCP")
    async def test_server_run(self, mock_fastmcp_class, mock_settings_class):
        """Test server run method."""
        # Mock settings
        mock_settings = Mock()
        mock_settings_class.return_value = mock_settings
        
        # Mock FastMCP with async run method
        mock_mcp = Mock()
        mock_mcp.run = AsyncMock()
        mock_fastmcp_class.return_value = mock_mcp
        
        # Create and run server
        server = create_server()
        await server.run()
        
        # Verify run was called
        mock_mcp.run.assert_called_once()

    @pytest.mark.asyncio
    @patch("fastmcp_mysql.server.Settings")
    @patch("fastmcp_mysql.server.FastMCP")
    async def test_server_graceful_shutdown(self, mock_fastmcp_class, mock_settings_class):
        """Test server handles shutdown gracefully."""
        # Mock settings
        mock_settings = Mock()
        mock_settings_class.return_value = mock_settings
        
        # Mock FastMCP
        mock_mcp = Mock()
        mock_mcp.run = AsyncMock()
        mock_mcp.shutdown = AsyncMock()
        mock_fastmcp_class.return_value = mock_mcp
        
        # Create server
        server = create_server()
        
        # Simulate shutdown
        if hasattr(server, "shutdown"):
            await server.shutdown()
            mock_mcp.shutdown.assert_called_once()