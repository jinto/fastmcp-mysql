"""Configuration management for FastMCP MySQL server."""

from typing import Dict, Any, Optional
from enum import Enum

from pydantic import Field, field_validator, AliasChoices
from pydantic_settings import BaseSettings


class LogLevel(str, Enum):
    """Valid log levels."""
    
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Settings(BaseSettings):
    """Configuration settings for MySQL server."""
    
    # MySQL connection settings
    host: str = Field(default="127.0.0.1", description="MySQL server host")
    port: int = Field(default=3306, description="MySQL server port")
    user: str = Field(description="MySQL username")
    password: str = Field(description="MySQL password")
    db: str = Field(description="MySQL database name")
    
    # Security settings
    allow_insert: bool = Field(
        default=False,
        description="Allow INSERT operations"
    )
    allow_update: bool = Field(
        default=False,
        description="Allow UPDATE operations"
    )
    allow_delete: bool = Field(
        default=False,
        description="Allow DELETE operations"
    )
    
    # Performance settings
    pool_size: int = Field(
        default=10,
        description="Connection pool size"
    )
    query_timeout: int = Field(
        default=30000,
        description="Query timeout in milliseconds"
    )
    cache_ttl: int = Field(
        default=60000,
        description="Cache TTL in milliseconds"
    )
    
    # Logging settings
    log_level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Logging level"
    )
    
    model_config = {
        "env_prefix": "MYSQL_",
        "case_sensitive": False,
        "extra": "ignore"
    }
    
    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        """Validate MySQL port is in valid range."""
        if not 1 <= v <= 65535:
            raise ValueError("Port must be between 1 and 65535")
        return v
    
    @field_validator("pool_size")
    @classmethod
    def validate_pool_size(cls, v: int) -> int:
        """Validate pool size is positive."""
        if v < 1:
            raise ValueError("Pool size must be at least 1")
        return v
    
    @field_validator("query_timeout", "cache_ttl")
    @classmethod
    def validate_positive_milliseconds(cls, v: int) -> int:
        """Validate timeout values are positive."""
        if v < 0:
            raise ValueError("Timeout values must be non-negative")
        return v
    
    @field_validator("log_level", mode="before")
    @classmethod
    def validate_log_level(cls, v: Any) -> str:
        """Validate and normalize log level."""
        if isinstance(v, str):
            v = v.upper()
            if v not in [level.value for level in LogLevel]:
                raise ValueError(f"Invalid log level: {v}")
        return v
    
    @property
    def connection_string_safe(self) -> str:
        """Get connection string with masked password."""
        return f"mysql://{self.user}:***@{self.host}:{self.port}/{self.db}"
    
    def to_dict_safe(self) -> Dict[str, Any]:
        """Convert settings to dictionary with masked sensitive values."""
        data = self.model_dump()
        # Mask sensitive fields
        if "password" in data:
            data["password"] = "***"
        return data