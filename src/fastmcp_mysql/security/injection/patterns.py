"""SQL injection patterns and detection rules."""

import re
from typing import List, Pattern, Tuple

# Compile patterns once for performance
COMMENT_PATTERNS: List[Pattern] = [
    re.compile(r"--\s*", re.IGNORECASE),  # SQL line comment
    re.compile(r"#\s*", re.IGNORECASE),   # MySQL comment
    re.compile(r"/\*.*?\*/", re.IGNORECASE | re.DOTALL),  # Block comment
]

UNION_PATTERN = re.compile(
    r"\bUNION\s+(ALL\s+)?SELECT\b",
    re.IGNORECASE
)

SEMICOLON_PATTERN = re.compile(r";\s*\S")  # Semicolon followed by non-whitespace

QUOTE_PATTERNS: List[Pattern] = [
    re.compile(r"'\s*(OR|AND)\s+.*?=", re.IGNORECASE),  # ' OR 1=1
    re.compile(r'"\s*(OR|AND)\s+.*?=', re.IGNORECASE),  # " OR 1=1
]

DANGEROUS_FUNCTIONS: List[Pattern] = [
    re.compile(r"\b(SLEEP|BENCHMARK|WAITFOR|DELAY|PG_SLEEP)\s*\(", re.IGNORECASE),
    re.compile(r"\b(LOAD_FILE|INTO\s+(OUT|DUMP)FILE)\s*\(", re.IGNORECASE),
    re.compile(r"\b(EXTRACTVALUE|UPDATEXML|XMLTYPE)\s*\(", re.IGNORECASE),
    re.compile(r"\b(EXEC|EXECUTE|CALL)\s+", re.IGNORECASE),
    re.compile(r"\b(ASCII|SUBSTRING|SUBSTR|CHAR|CHR)\s*\(", re.IGNORECASE),
    re.compile(r"\b(CONCAT|GROUP_CONCAT)\s*\(.*@@", re.IGNORECASE),
]

SYSTEM_VARIABLE_PATTERN = re.compile(r"@@\w+", re.IGNORECASE)

HEX_PATTERN = re.compile(r"0x[0-9a-fA-F]+")

ENCODED_PATTERNS: List[Tuple[Pattern, str]] = [
    (re.compile(r"%27|%22"), "URL encoded quotes"),
    (re.compile(r"\\u00[2-3][0-9a-fA-F]"), "Unicode encoded quotes"),
    (re.compile(r"&(#39|#34|quot|apos);"), "HTML entity encoded quotes"),
]

# Patterns that indicate direct string concatenation in query
UNSAFE_QUERY_PATTERNS: List[Pattern] = [
    re.compile(r"'\s*\+\s*\w+\s*\+\s*'"),  # String concatenation
    re.compile(r'"\s*\+\s*\w+\s*\+\s*"'),
    re.compile(r"'\s*\|\|\s*\w+\s*\|\|\s*'"),  # Oracle/PostgreSQL concat
    re.compile(r"CONCAT\s*\([^)]*\$\w+[^)]*\)", re.IGNORECASE),  # PHP variable in CONCAT
]

# Blind SQL injection patterns
BLIND_INJECTION_PATTERNS: List[Pattern] = [
    re.compile(r"\bIF\s*\([^)]*,\s*SLEEP\s*\(", re.IGNORECASE),
    re.compile(r"\b(ASCII|ORD)\s*\(\s*SUBSTRING", re.IGNORECASE),
    re.compile(r"\bCASE\s+WHEN\s+.*\s+THEN\s+SLEEP", re.IGNORECASE),
]

# Common SQL injection payloads in parameters
PARAMETER_INJECTION_PATTERNS = [
    # Classic injection
    (r"'\s*(OR|AND)\s+'?\d+'?\s*=\s*'?\d+'?", "Classic SQL injection"),
    (r'"\s*(OR|AND)\s+"?\d+"?\s*=\s*"?\d+"?', "Classic SQL injection"),
    
    # Comment-based
    (r"'\s*--", "SQL comment injection"),
    (r"'\s*#", "MySQL comment injection"),
    (r"'\s*/\*", "Block comment injection"),
    
    # Union-based
    (r"'\s*UNION\s+(ALL\s+)?SELECT", "UNION injection"),
    
    # Function calls
    (r"'\s*AND\s+\w+\s*\(", "Function-based injection"),
    (r"'\s*OR\s+\w+\s*\(", "Function-based injection"),
    
    # Stacked queries
    (r"';\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)", "Stacked query injection"),
    
    # Boolean logic
    (r"'\s*(AND|OR)\s+\d+\s*[<>=]+\s*\d+", "Boolean-based injection"),
]