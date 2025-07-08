"""Security configuration for FastMCP MySQL."""

from typing import Dict, List, Optional
from enum import Enum
from pydantic import BaseModel, Field


class RateLimitAlgorithm(str, Enum):
    """Available rate limiting algorithms."""
    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"


class FilterMode(str, Enum):
    """Query filtering modes."""
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
    COMBINED = "combined"  # Both whitelist and blacklist


class SecuritySettings(BaseModel):
    """Security configuration settings."""
    
    # SQL Injection Prevention
    enable_injection_detection: bool = Field(
        default=True,
        description="Enable SQL injection detection"
    )
    max_query_length: int = Field(
        default=10000,
        description="Maximum allowed query length"
    )
    max_parameter_length: int = Field(
        default=1000,
        description="Maximum allowed parameter length"
    )
    
    # Query Filtering
    filter_mode: FilterMode = Field(
        default=FilterMode.BLACKLIST,
        description="Query filtering mode"
    )
    whitelist_patterns: List[str] = Field(
        default_factory=list,
        description="Regex patterns for allowed queries"
    )
    blacklist_patterns: List[str] = Field(
        default_factory=lambda: [
            # DDL operations (already blocked in query validator)
            r".*\b(CREATE|DROP|ALTER|TRUNCATE)\s+(TABLE|DATABASE|INDEX|VIEW)\b.*",
            # System database access
            r".*\b(information_schema|mysql|performance_schema|sys)\b\.",
            # File operations
            r".*\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b.*",
            # User management
            r".*\b(CREATE|DROP|ALTER)\s+USER\b.*",
            r".*\b(GRANT|REVOKE)\b.*",
            # Dangerous functions
            r".*\b(SLEEP|BENCHMARK|GET_LOCK|RELEASE_LOCK)\s*\(.*",
            # Stored procedures
            r".*\b(CALL|EXECUTE)\s+.*",
        ],
        description="Regex patterns for blocked queries"
    )
    
    # Rate Limiting
    enable_rate_limiting: bool = Field(
        default=True,
        description="Enable rate limiting"
    )
    rate_limit_algorithm: RateLimitAlgorithm = Field(
        default=RateLimitAlgorithm.TOKEN_BUCKET,
        description="Rate limiting algorithm"
    )
    rate_limit_requests_per_minute: int = Field(
        default=60,
        description="Maximum requests per minute"
    )
    rate_limit_burst_size: int = Field(
        default=10,
        description="Burst size for token bucket"
    )
    rate_limit_per_user: Dict[str, int] = Field(
        default_factory=dict,
        description="Per-user rate limits"
    )
    
    # Security Logging
    log_security_events: bool = Field(
        default=True,
        description="Log security events"
    )
    log_rejected_queries: bool = Field(
        default=True,
        description="Log rejected queries"
    )
    audit_all_queries: bool = Field(
        default=False,
        description="Audit all queries (performance impact)"
    )