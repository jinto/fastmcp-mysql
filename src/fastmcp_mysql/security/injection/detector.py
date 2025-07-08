"""SQL injection detector implementation."""

import re
import urllib.parse
from typing import List, Optional, Any
from html import unescape

from ..interfaces import InjectionDetector
from .patterns import (
    COMMENT_PATTERNS, UNION_PATTERN, SEMICOLON_PATTERN, QUOTE_PATTERNS,
    DANGEROUS_FUNCTIONS, SYSTEM_VARIABLE_PATTERN, HEX_PATTERN,
    ENCODED_PATTERNS, UNSAFE_QUERY_PATTERNS, BLIND_INJECTION_PATTERNS,
    PARAMETER_INJECTION_PATTERNS
)


class SQLInjectionDetector(InjectionDetector):
    """Detects SQL injection attempts in queries and parameters."""
    
    def __init__(self, strict_mode: bool = True):
        """
        Initialize the detector.
        
        Args:
            strict_mode: If True, be more aggressive in detection
        """
        self.strict_mode = strict_mode
    
    def detect(self, query: str, params: Optional[tuple] = None) -> List[str]:
        """
        Detect potential SQL injection patterns in a query.
        
        Args:
            query: SQL query to analyze
            params: Query parameters (not used in query detection)
            
        Returns:
            List of detected threats. Empty if safe.
        """
        threats = []
        
        # First decode the query to catch encoded attacks
        decoded_query = self._decode_parameter(query)
        
        # Check both original and decoded versions
        for check_query in [query, decoded_query]:
            # Check for unsafe query construction patterns
            for pattern in UNSAFE_QUERY_PATTERNS:
                if pattern.search(check_query):
                    threats.append("Unsafe query construction detected")
                    break
            
            # Check if query uses placeholders properly
            if not self._has_proper_placeholders(check_query):
                # Check for quotes that might indicate injection
                if "'" in check_query or '"' in check_query:
                    # Check if it's within string literals
                    if self._has_unescaped_quotes(check_query):
                        threats.append("Unescaped quotes in query")
            
            # Check for dangerous functions
            for pattern in DANGEROUS_FUNCTIONS:
                if pattern.search(check_query):
                    threats.append(f"Dangerous function detected")
            
            # Check for UNION injection
            if UNION_PATTERN.search(check_query):
                threats.append("UNION clause detected")
            
            # Check for comment patterns (often used to bypass filters)
            for pattern in COMMENT_PATTERNS:
                if pattern.search(check_query):
                    threats.append("SQL comment detected")
            
            # Check for system variables access
            if SYSTEM_VARIABLE_PATTERN.search(check_query):
                threats.append("System variable access detected")
            
            # Check for blind injection patterns
            for pattern in BLIND_INJECTION_PATTERNS:
                if pattern.search(check_query):
                    threats.append("Blind SQL injection pattern detected")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_threats = []
        for threat in threats:
            if threat not in seen:
                seen.add(threat)
                unique_threats.append(threat)
        
        return unique_threats
    
    def validate_parameters(self, params: tuple) -> List[str]:
        """
        Validate query parameters for injection attempts.
        
        Args:
            params: Query parameters to validate
            
        Returns:
            List of detected threats. Empty if safe.
        """
        threats = []
        
        for param in params:
            if param is None:
                continue
                
            # Convert to string for analysis
            param_str = str(param)
            
            # Check parameter length
            if len(param_str) > 1000:  # Configurable
                threats.append(f"Parameter too long: {len(param_str)} characters")
                continue
            
            # Decode if needed
            decoded_param = self._decode_parameter(param_str)
            
            # Check for encoded attacks
            if decoded_param != param_str:
                for pattern, description in ENCODED_PATTERNS:
                    if pattern.search(param_str):
                        threats.append(f"Encoded injection attempt: {description}")
            
            # Check for SQL injection patterns
            param_threats = self._check_injection_patterns(decoded_param)
            threats.extend(param_threats)
            
            # Check for multiple statements
            if ';' in decoded_param and self._has_multiple_statements(decoded_param):
                threats.append("Multiple statements detected")
            
            # Check for hex values that might be SQL
            if HEX_PATTERN.match(param_str):
                try:
                    hex_decoded = bytes.fromhex(param_str[2:]).decode('utf-8', errors='ignore')
                    # Check if decoded hex contains SQL patterns
                    hex_threats = self._check_injection_patterns(hex_decoded)
                    if hex_threats or any(keyword in hex_decoded.upper() for keyword in ['SELECT', 'UNION', 'DROP', 'OR', 'AND']):
                        threats.append("Hex-encoded SQL detected")
                except:
                    pass
        
        return threats
    
    def _has_proper_placeholders(self, query: str) -> bool:
        """Check if query uses proper parameter placeholders."""
        # Check for %s (MySQL/psycopg2 style) or ? (standard style)
        return '%s' in query or '?' in query
    
    def _has_unescaped_quotes(self, query: str) -> bool:
        """Check for unescaped quotes that might indicate injection."""
        # Simple heuristic: count quotes and check if they're balanced
        # This is not perfect but catches many cases
        single_quotes = query.count("'")
        double_quotes = query.count('"')
        
        # Check for odd number of quotes (likely unescaped)
        if single_quotes % 2 != 0 or double_quotes % 2 != 0:
            return True
        
        # Check for quote followed by SQL keywords
        for pattern in QUOTE_PATTERNS:
            if pattern.search(query):
                return True
        
        return False
    
    def _decode_parameter(self, param: str) -> str:
        """Decode parameter to catch encoded injection attempts."""
        decoded = param
        
        # URL decode
        try:
            decoded = urllib.parse.unquote(decoded)
        except:
            pass
        
        # HTML entity decode
        try:
            decoded = unescape(decoded)
        except:
            pass
        
        # Unicode decode
        try:
            decoded = decoded.encode().decode('unicode_escape')
        except:
            pass
        
        return decoded
    
    def _check_injection_patterns(self, param: str) -> List[str]:
        """Check parameter for common injection patterns."""
        threats = []
        
        # Check against known patterns
        for pattern_str, description in PARAMETER_INJECTION_PATTERNS:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            if pattern.search(param):
                threats.append(description)
        
        # Check for dangerous functions in parameters
        for func_pattern in DANGEROUS_FUNCTIONS:
            if func_pattern.search(param):
                threats.append("Dangerous function in parameter")
        
        # Special case: O'Brien should be safe, but admin' OR '1'='1 should not
        if "'" in param:
            # Check if it's followed by SQL keywords
            if re.search(r"'\s*(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE)", param, re.IGNORECASE):
                threats.append("SQL keyword after quote")
        
        return threats
    
    def _has_multiple_statements(self, param: str) -> bool:
        """Check if parameter contains multiple SQL statements."""
        # Look for semicolon followed by SQL keywords
        if re.search(r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)", param, re.IGNORECASE):
            return True
        
        # Check with our semicolon pattern
        if SEMICOLON_PATTERN.search(param):
            return True
        
        return False