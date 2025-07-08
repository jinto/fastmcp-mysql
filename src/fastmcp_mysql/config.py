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
    
    # Cache settings
    cache_enabled: bool = Field(
        default=True,
        description="Enable query result caching"
    )
    cache_max_size: int = Field(
        default=1000,
        description="Maximum number of cache entries"
    )
    cache_eviction_policy: str = Field(
        default="lru",
        description="Cache eviction policy (lru, ttl)"
    )
    cache_cleanup_interval: float = Field(
        default=60.0,
        description="Cache cleanup interval in seconds"
    )
    cache_invalidation_mode: str = Field(
        default="aggressive",
        description="Cache invalidation strategy (aggressive, conservative, targeted)"
    )
    
    # Performance settings
    streaming_chunk_size: int = Field(
        default=1000,
        description="Default chunk size for streaming queries"
    )
    pagination_default_size: int = Field(
        default=10,
        description="Default page size for paginated queries"
    )
    pagination_max_size: int = Field(
        default=1000,
        description="Maximum allowed page size"
    )
    
    # Logging settings
    log_level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Logging level"
    )
    log_dir: Optional[str] = Field(
        default=None,
        description="Directory for log files"
    )
    enable_file_logging: bool = Field(
        default=False,
        description="Enable file logging with rotation"
    )
    
    # Observability settings
    enable_metrics: bool = Field(
        default=True,
        description="Enable metrics collection"
    )
    enable_health_checks: bool = Field(
        default=True,
        description="Enable health check endpoints"
    )
    enable_tracing: bool = Field(
        default=False,
        description="Enable distributed tracing"
    )
    otlp_endpoint: Optional[str] = Field(
        default=None,
        description="OpenTelemetry collector endpoint"
    )
    slow_query_threshold_ms: int = Field(
        default=1000,
        description="Threshold for slow query logging in milliseconds"
    )
    metrics_export_interval: int = Field(
        default=60,
        description="Metrics export interval in seconds"
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
    
    @field_validator("cache_max_size", "streaming_chunk_size", "pagination_default_size", "pagination_max_size")
    @classmethod
    def validate_positive_integers(cls, v: int) -> int:
        """Validate positive integer values."""
        if v < 1:
            raise ValueError("Value must be at least 1")
        return v
    
    @field_validator("cache_eviction_policy")
    @classmethod
    def validate_eviction_policy(cls, v: str) -> str:
        """Validate cache eviction policy."""
        valid_policies = ["lru", "ttl", "fifo"]
        if v.lower() not in valid_policies:
            raise ValueError(f"Invalid eviction policy. Must be one of: {', '.join(valid_policies)}")
        return v.lower()
    
    @field_validator("cache_invalidation_mode")
    @classmethod
    def validate_invalidation_mode(cls, v: str) -> str:
        """Validate cache invalidation mode."""
        valid_modes = ["aggressive", "conservative", "targeted"]
        if v.lower() not in valid_modes:
            raise ValueError(f"Invalid invalidation mode. Must be one of: {', '.join(valid_modes)}")
        return v.lower()
    
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