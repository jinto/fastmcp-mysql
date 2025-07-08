"""Tests for SQL injection detection and prevention."""

import pytest
from typing import List

from fastmcp_mysql.security.interfaces import InjectionDetector
from fastmcp_mysql.security.exceptions import InjectionError
from fastmcp_mysql.security import SecurityManager, SecurityContext, SecuritySettings


class TestSQLInjectionDetection:
    """Test SQL injection detection functionality."""
    
    def test_basic_injection_detector_interface(self):
        """Test that InjectionDetector interface is properly defined."""
        # This will fail until we implement the detector
        from fastmcp_mysql.security.interfaces import InjectionDetector
        
        # Interface should require these methods
        assert hasattr(InjectionDetector, 'detect')
        assert hasattr(InjectionDetector, 'validate_parameters')
    
    @pytest.mark.asyncio
    async def test_injection_patterns_detected(self, sql_injection_payloads):
        """Test that common SQL injection patterns are detected."""
        # This test will fail until we implement the detector
        from fastmcp_mysql.security.injection import SQLInjectionDetector
        
        detector = SQLInjectionDetector()
        
        for payload in sql_injection_payloads:
            # Test as parameter
            threats = detector.validate_parameters((payload,))
            assert threats, f"Failed to detect injection in parameter: {payload}"
            
            # Test in query string (should detect when not using placeholders)
            query = f"SELECT * FROM users WHERE username = '{payload}'"
            threats = detector.detect(query)
            assert threats, f"Failed to detect injection in query: {query[:50]}..."
    
    @pytest.mark.asyncio
    async def test_safe_queries_allowed(self, safe_queries):
        """Test that safe queries are not flagged."""
        from fastmcp_mysql.security.injection import SQLInjectionDetector
        
        detector = SQLInjectionDetector()
        
        for query in safe_queries:
            threats = detector.detect(query)
            assert not threats, f"Safe query incorrectly flagged: {query}"
    
    def test_parameter_validation(self, test_parameters):
        """Test parameter validation for injection attempts."""
        from fastmcp_mysql.security.injection import SQLInjectionDetector
        
        detector = SQLInjectionDetector()
        
        # Safe parameters should pass
        for params in test_parameters["safe"]:
            threats = detector.validate_parameters(params)
            assert not threats, f"Safe parameter incorrectly flagged: {params}"
        
        # Dangerous parameters should be detected
        for params in test_parameters["dangerous"]:
            threats = detector.validate_parameters(params)
            assert threats, f"Failed to detect dangerous parameter: {params}"
    
    def test_encoded_injection_detection(self):
        """Test detection of encoded injection attempts."""
        from fastmcp_mysql.security.injection import SQLInjectionDetector
        
        detector = SQLInjectionDetector()
        
        encoded_attacks = [
            # URL encoding
            "admin%27%20OR%20%271%27%3D%271",
            # Unicode encoding
            "admin\\u0027 OR \\u00271\\u0027=\\u00271",
            # Hex encoding
            "0x61646d696e2720204f522027312723443237",
        ]
        
        for attack in encoded_attacks:
            threats = detector.validate_parameters((attack,))
            assert threats, f"Failed to detect encoded attack: {attack}"
    
    def test_context_aware_detection(self):
        """Test context-aware injection detection."""
        from fastmcp_mysql.security.injection import SQLInjectionDetector
        
        detector = SQLInjectionDetector()
        
        # Same string might be safe or dangerous depending on context
        value = "O'Brien"  # Legitimate name with apostrophe
        
        # Should be safe as parameter
        threats = detector.validate_parameters((value,))
        assert not threats
        
        # Should be dangerous in direct query
        query = f"SELECT * FROM users WHERE name = '{value}'"
        threats = detector.detect(query)
        # This should detect the pattern of unescaped quotes in query
        assert threats or "'" not in query  # Either detected or properly escaped
    
    @pytest.mark.asyncio
    async def test_security_manager_injection_prevention(self, security_settings):
        """Test SecurityManager prevents SQL injection."""
        from fastmcp_mysql.security.injection import SQLInjectionDetector
        
        detector = SQLInjectionDetector()
        manager = SecurityManager(
            settings=security_settings,
            injection_detector=detector
        )
        
        # Test with injection in parameter
        with pytest.raises(InjectionError) as exc:
            await manager.validate_query(
                "SELECT * FROM users WHERE id = %s",
                ("1' OR '1'='1",)
            )
        assert "injection" in str(exc.value).lower()
        
        # Test with injection in query
        with pytest.raises(InjectionError) as exc:
            await manager.validate_query(
                "SELECT * FROM users WHERE id = '1' OR '1'='1'"
            )
        assert "injection" in str(exc.value).lower()
    
    def test_multi_statement_detection(self):
        """Test detection of multi-statement attacks."""
        from fastmcp_mysql.security.injection import SQLInjectionDetector
        
        detector = SQLInjectionDetector()
        
        multi_statement_attacks = [
            "1'; DROP TABLE users--",
            "1'; INSERT INTO admins VALUES ('hacker', 'password')--",
            "1'; UPDATE users SET role='admin' WHERE username='hacker'--",
        ]
        
        for attack in multi_statement_attacks:
            threats = detector.validate_parameters((attack,))
            assert threats, f"Failed to detect multi-statement attack: {attack}"
            assert any("multiple statements" in t.lower() or "semicolon" in t.lower() 
                      for t in threats)
    
    def test_comment_based_injection(self):
        """Test detection of comment-based injection."""
        from fastmcp_mysql.security.injection import SQLInjectionDetector
        
        detector = SQLInjectionDetector()
        
        comment_attacks = [
            "admin'--",
            "admin'#",
            "admin'/*comment*/",
            "admin' -- comment",
            "admin' # comment",
        ]
        
        for attack in comment_attacks:
            threats = detector.validate_parameters((attack,))
            assert threats, f"Failed to detect comment-based attack: {attack}"
            assert any("comment" in t.lower() for t in threats)
    
    def test_function_based_injection(self):
        """Test detection of function-based injection."""
        from fastmcp_mysql.security.injection import SQLInjectionDetector
        
        detector = SQLInjectionDetector()
        
        function_attacks = [
            "1' AND SLEEP(5)--",
            "1' AND BENCHMARK(1000000,MD5('test'))--",
            "1' AND LOAD_FILE('/etc/passwd')--",
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
        ]
        
        for attack in function_attacks:
            threats = detector.validate_parameters((attack,))
            assert threats, f"Failed to detect function-based attack: {attack}"
    
    def test_blind_injection_detection(self):
        """Test detection of blind SQL injection techniques."""
        from fastmcp_mysql.security.injection import SQLInjectionDetector
        
        detector = SQLInjectionDetector()
        
        blind_attacks = [
            # Time-based
            "1' AND IF(1=1,SLEEP(5),0)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            # Boolean-based
            "1' AND ASCII(SUBSTRING((SELECT password FROM users),1,1))>65--",
            "1' AND (SELECT COUNT(*) FROM users)>10--",
        ]
        
        for attack in blind_attacks:
            threats = detector.validate_parameters((attack,))
            assert threats, f"Failed to detect blind injection: {attack}"
    
    def test_union_based_injection(self):
        """Test detection of UNION-based injection."""
        from fastmcp_mysql.security.injection import SQLInjectionDetector
        
        detector = SQLInjectionDetector()
        
        union_attacks = [
            "1' UNION SELECT * FROM users--",
            "1' UNION ALL SELECT NULL,NULL,NULL--",
            "1' UNION SELECT username,password FROM users--",
        ]
        
        for attack in union_attacks:
            threats = detector.validate_parameters((attack,))
            assert threats, f"Failed to detect UNION attack: {attack}"
            assert any("union" in t.lower() for t in threats)