#!/usr/bin/env python3
"""Fix type annotations for mypy errors."""

import re
import sys

def fix_file(filename):
    with open(filename, 'r') as f:
        content = f.read()
    
    # Replace patterns
    patterns = [
        # Methods without return type annotations
        (r'def record_query\(\s*self,\s*query_type: str,\s*duration_ms: float,\s*success: bool,\s*query: str,\s*threshold_ms: float = 1000,\s*\):', 
         r'def record_query(\n        self,\n        query_type: str,\n        duration_ms: float,\n        success: bool,\n        query: str,\n        threshold_ms: float = 1000,\n    ) -> None:'),
        (r'def update\(self, total: int, active: int, max_size: int\):',
         r'def update(self, total: int, active: int, max_size: int) -> None:'),
        (r'def record_wait_time\(self, wait_ms: float\):',
         r'def record_wait_time(self, wait_ms: float) -> None:'),
        (r'def record_connection_error\(self\):',
         r'def record_connection_error(self) -> None:'),
        (r'def record_hit\(self\):',
         r'def record_hit(self) -> None:'),
        (r'def record_miss\(self\):',
         r'def record_miss(self) -> None:'),
        (r'def record_eviction\(self\):',
         r'def record_eviction(self) -> None:'),
        (r'def update_size\(self, current: int, max_size: int\):',
         r'def update_size(self, current: int, max_size: int) -> None:'),
        (r'def record_error\(\s*self, error_type: str, error_msg: str, context: dict\[str, Any\] \| None = None\s*\):',
         r'def record_error(\n        self, error_type: str, error_msg: str, context: dict[str, Any] | None = None\n    ) -> None:'),
        (r'window_errors = defaultdict\(int\)',
         r'window_errors: dict[str, int] = defaultdict(int)'),
        (r'def __init__\(self\):',
         r'def __init__(self) -> None:'),
        (r'def update_connection_pool\(self, total: int, active: int, max_size: int\):',
         r'def update_connection_pool(self, total: int, active: int, max_size: int) -> None:'),
        (r'def record_cache_hit\(self\):',
         r'def record_cache_hit(self) -> None:'),
        (r'def record_cache_miss\(self\):',
         r'def record_cache_miss(self) -> None:'),
        (r'def register_custom_metric\(self, name: str, value: Any\):',
         r'def register_custom_metric(self, name: str, value: Any) -> None:'),
        (r'def register_callback\(self, callback: Callable\[\[dict\[str, Any\]\], None\]\):',
         r'def register_callback(self, callback: Callable[[dict[str, Any]], None]) -> None:'),
    ]
    
    # Apply all patterns
    for pattern, replacement in patterns:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE | re.DOTALL)
    
    # Write back
    with open(filename, 'w') as f:
        f.write(content)
    
    print(f"Fixed {filename}")

if __name__ == "__main__":
    files = [
        "src/fastmcp_mysql/observability/metrics.py",
        "src/fastmcp_mysql/observability/health.py",
        "src/fastmcp_mysql/observability/logging.py",
        "src/fastmcp_mysql/cache/ttl_cache.py",
        "src/fastmcp_mysql/cache/lru_cache.py",
        "src/fastmcp_mysql/cache/interfaces.py",
        "src/fastmcp_mysql/cache/invalidator.py",
        "src/fastmcp_mysql/monitoring.py",
        "src/fastmcp_mysql/security/filtering/blacklist.py",
        "src/fastmcp_mysql/config.py",
        "src/fastmcp_mysql/connection.py",
        "src/fastmcp_mysql/server.py",
        "src/fastmcp_mysql/server_enhanced.py",
    ]
    
    for file in files:
        try:
            fix_file(file)
        except Exception as e:
            print(f"Error fixing {file}: {e}")