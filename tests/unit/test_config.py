"""Unit tests for configuration management."""

import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from fastmcp_mysql.config import Settings


class TestSettings:
    """Test the Settings configuration class."""

    def test_required_fields(self):
        """Test that required fields raise ValidationError when missing."""
        with pytest.raises(ValidationError) as exc_info:
            Settings(_env_file=None)
        
        errors = exc_info.value.errors()
        required_fields = {"user", "password", "db"}
        missing_fields = {error["loc"][0] for error in errors}
        
        assert required_fields == missing_fields

    def test_default_values(self):
        """Test default values are set correctly."""
        with patch.dict(os.environ, {
            "MYSQL_USER": "testuser",
            "MYSQL_PASSWORD": "testpass",
            "MYSQL_DB": "testdb"
        }):
            settings = Settings(_env_file=None)
            
            # Connection defaults
            assert settings.host == "127.0.0.1"
            assert settings.port == 3306
            
            # Security defaults (all false)
            assert settings.allow_insert is False
            assert settings.allow_update is False
            assert settings.allow_delete is False
            
            # Performance defaults
            assert settings.pool_size == 10
            assert settings.query_timeout == 30000
            assert settings.cache_ttl == 60000
            
            # Logging default
            assert settings.log_level == "INFO"

    def test_environment_variables(self):
        """Test loading configuration from environment variables."""
        env_vars = {
            "MYSQL_HOST": "192.168.1.100",
            "MYSQL_PORT": "3307",
            "MYSQL_USER": "myuser",
            "MYSQL_PASSWORD": "mypass",
            "MYSQL_DB": "mydb",
            "MYSQL_ALLOW_INSERT": "true",
            "MYSQL_ALLOW_UPDATE": "TRUE",
            "MYSQL_ALLOW_DELETE": "1",
            "MYSQL_POOL_SIZE": "20",
            "MYSQL_QUERY_TIMEOUT": "60000",
            "MYSQL_CACHE_TTL": "120000",
            "MYSQL_LOG_LEVEL": "DEBUG"
        }
        
        with patch.dict(os.environ, env_vars):
            settings = Settings(_env_file=None)
            
            assert settings.host == "192.168.1.100"
            assert settings.port == 3307
            assert settings.user == "myuser"
            assert settings.password == "mypass"
            assert settings.db == "mydb"
            assert settings.allow_insert is True
            assert settings.allow_update is True
            assert settings.allow_delete is True
            assert settings.pool_size == 20
            assert settings.query_timeout == 60000
            assert settings.cache_ttl == 120000
            assert settings.log_level == "DEBUG"

    def test_invalid_port(self):
        """Test validation for invalid port numbers."""
        env_vars = {
            "MYSQL_USER": "testuser",
            "MYSQL_PASSWORD": "testpass",
            "MYSQL_DB": "testdb",
            "MYSQL_PORT": "invalid"
        }
        
        with patch.dict(os.environ, env_vars):
            with pytest.raises(ValidationError) as exc_info:
                Settings(_env_file=None)
            
            errors = exc_info.value.errors()
            assert any(error["loc"][0] == "port" for error in errors)

    def test_pool_size_validation(self):
        """Test validation for pool size."""
        env_vars = {
            "MYSQL_USER": "testuser",
            "MYSQL_PASSWORD": "testpass",
            "MYSQL_DB": "testdb",
            "MYSQL_POOL_SIZE": "0"
        }
        
        with patch.dict(os.environ, env_vars):
            with pytest.raises(ValidationError) as exc_info:
                Settings(_env_file=None)
            
            errors = exc_info.value.errors()
            assert any(error["loc"][0] == "pool_size" for error in errors)

    def test_log_level_validation(self):
        """Test validation for log level."""
        env_vars = {
            "MYSQL_USER": "testuser",
            "MYSQL_PASSWORD": "testpass",
            "MYSQL_DB": "testdb",
            "MYSQL_LOG_LEVEL": "INVALID"
        }
        
        with patch.dict(os.environ, env_vars):
            with pytest.raises(ValidationError) as exc_info:
                Settings(_env_file=None)
            
            errors = exc_info.value.errors()
            assert any(error["loc"][0] == "log_level" for error in errors)

    def test_connection_string_property(self):
        """Test the connection string property."""
        with patch.dict(os.environ, {
            "MYSQL_USER": "testuser",
            "MYSQL_PASSWORD": "testpass",
            "MYSQL_DB": "testdb"
        }):
            settings = Settings(_env_file=None)
            
            expected = "mysql://testuser:***@127.0.0.1:3306/testdb"
            assert settings.connection_string_safe == expected

    def test_to_dict_masks_password(self):
        """Test that to_dict masks sensitive information."""
        with patch.dict(os.environ, {
            "MYSQL_USER": "testuser",
            "MYSQL_PASSWORD": "supersecret",
            "MYSQL_DB": "testdb"
        }):
            settings = Settings(_env_file=None)
            settings_dict = settings.to_dict_safe()
            
            # Check if password is masked
            assert settings_dict.get("password") == "***"
            assert "supersecret" not in str(settings_dict)