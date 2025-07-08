"""Pytest configuration and shared fixtures."""

import os
import sys
from pathlib import Path

import pytest
from unittest.mock import patch

# Add src to path for imports
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))


@pytest.fixture
def clean_env():
    """Fixture to provide clean environment variables."""
    # Store original environment
    original_env = os.environ.copy()
    
    # Clear MySQL-related environment variables
    mysql_keys = [k for k in os.environ.keys() if k.startswith("MYSQL_")]
    for key in mysql_keys:
        del os.environ[key]
    
    yield
    
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def basic_mysql_env():
    """Fixture to provide basic MySQL environment variables."""
    env_vars = {
        "MYSQL_USER": "testuser",
        "MYSQL_PASS": "testpass",
        "MYSQL_DB": "testdb"
    }
    
    with patch.dict(os.environ, env_vars):
        yield env_vars


@pytest.fixture
def full_mysql_env():
    """Fixture to provide full MySQL environment variables."""
    env_vars = {
        "MYSQL_HOST": "localhost",
        "MYSQL_PORT": "3306",
        "MYSQL_USER": "testuser",
        "MYSQL_PASS": "testpass",
        "MYSQL_DB": "testdb",
        "MYSQL_ALLOW_INSERT": "false",
        "MYSQL_ALLOW_UPDATE": "false",
        "MYSQL_ALLOW_DELETE": "false",
        "MYSQL_POOL_SIZE": "10",
        "MYSQL_QUERY_TIMEOUT": "30000",
        "MYSQL_CACHE_TTL": "60000",
        "MYSQL_LOG_LEVEL": "INFO"
    }
    
    with patch.dict(os.environ, env_vars):
        yield env_vars