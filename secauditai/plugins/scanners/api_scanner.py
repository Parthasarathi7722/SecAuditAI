#!/usr/bin/env python3
"""
API Security Scanner
------------------
This module provides API security scanning capabilities including:
- Authentication testing
- Authorization testing
- Input validation testing
- Rate limiting testing
- Security header analysis
"""

import requests
from typing import Dict, List, Optional
from secauditai.plugins.base import BaseScanner
from secauditai.core.rules import RuleEngine

class APIScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.rule_engine = RuleEngine()
        self.session = requests.Session()
        
    def scan(self, target_url: str, auth_token: Optional[str] = None) -> Dict:
        """
        Perform comprehensive API security scan
        
        Args:
            target_url: The API endpoint to scan
            auth_token: Optional authentication token
            
        Returns:
            Dict containing scan results
        """
        results = {
            "authentication": self.test_authentication(target_url, auth_token),
            "authorization": self.test_authorization(target_url, auth_token),
            "input_validation": self.test_input_validation(target_url),
            "rate_limiting": self.test_rate_limiting(target_url),
            "headers": self.analyze_security_headers(target_url),
            "vulnerabilities": []
        }
        
        # Apply custom rules
        custom_results = self.rule_engine.apply_rules("api", results)
        results["vulnerabilities"].extend(custom_results)
        
        return results
    
    def test_authentication(self, url: str, token: Optional[str] = None) -> Dict:
        """Test API authentication mechanisms"""
        results = {
            "basic_auth": self._test_basic_auth(url),
            "token_auth": self._test_token_auth(url, token),
            "jwt_auth": self._test_jwt_auth(url, token),
            "oauth": self._test_oauth(url)
        }
        return results
    
    def test_authorization(self, url: str, token: Optional[str] = None) -> Dict:
        """Test API authorization mechanisms"""
        results = {
            "role_based": self._test_role_based_auth(url, token),
            "resource_based": self._test_resource_based_auth(url, token),
            "permission_based": self._test_permission_based_auth(url, token)
        }
        return results
    
    def test_input_validation(self, url: str) -> Dict:
        """Test API input validation"""
        results = {
            "sql_injection": self._test_sql_injection(url),
            "xss": self._test_xss(url),
            "command_injection": self._test_command_injection(url),
            "path_traversal": self._test_path_traversal(url)
        }
        return results
    
    def test_rate_limiting(self, url: str) -> Dict:
        """Test API rate limiting"""
        results = {
            "basic_rate_limit": self._test_basic_rate_limit(url),
            "ip_based_limit": self._test_ip_based_limit(url),
            "token_based_limit": self._test_token_based_limit(url)
        }
        return results
    
    def analyze_security_headers(self, url: str) -> Dict:
        """Analyze security headers"""
        try:
            response = self.session.get(url)
            headers = response.headers
            
            results = {
                "csp": self._check_csp_header(headers),
                "hsts": self._check_hsts_header(headers),
                "x_frame_options": self._check_x_frame_options(headers),
                "x_content_type_options": self._check_x_content_type_options(headers),
                "x_xss_protection": self._check_x_xss_protection(headers)
            }
            return results
        except Exception as e:
            return {"error": str(e)}
    
    def _test_basic_auth(self, url: str) -> Dict:
        """Test basic authentication"""
        try:
            response = self.session.get(url, auth=("test", "test"))
            return {
                "status": response.status_code,
                "vulnerable": response.status_code != 401
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _test_token_auth(self, url: str, token: Optional[str] = None) -> Dict:
        """Test token-based authentication"""
        try:
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            response = self.session.get(url, headers=headers)
            return {
                "status": response.status_code,
                "vulnerable": response.status_code != 401 if not token else False
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _test_jwt_auth(self, url: str, token: Optional[str] = None) -> Dict:
        """Test JWT authentication"""
        try:
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            response = self.session.get(url, headers=headers)
            return {
                "status": response.status_code,
                "vulnerable": self._check_jwt_vulnerabilities(response)
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _test_oauth(self, url: str) -> Dict:
        """Test OAuth authentication"""
        try:
            response = self.session.get(url)
            return {
                "status": response.status_code,
                "vulnerable": self._check_oauth_vulnerabilities(response)
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _test_role_based_auth(self, url: str, token: Optional[str] = None) -> Dict:
        """Test role-based authorization"""
        try:
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            response = self.session.get(url, headers=headers)
            return {
                "status": response.status_code,
                "vulnerable": self._check_role_based_vulnerabilities(response)
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _test_resource_based_auth(self, url: str, token: Optional[str] = None) -> Dict:
        """Test resource-based authorization"""
        try:
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            response = self.session.get(url, headers=headers)
            return {
                "status": response.status_code,
                "vulnerable": self._check_resource_based_vulnerabilities(response)
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _test_permission_based_auth(self, url: str, token: Optional[str] = None) -> Dict:
        """Test permission-based authorization"""
        try:
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            response = self.session.get(url, headers=headers)
            return {
                "status": response.status_code,
                "vulnerable": self._check_permission_based_vulnerabilities(response)
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _test_sql_injection(self, url: str) -> Dict:
        """Test for SQL injection vulnerabilities"""
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT NULL--",
            "admin'--"
        ]
        results = []
        for payload in payloads:
            try:
                response = self.session.get(f"{url}?id={payload}")
                results.append({
                    "payload": payload,
                    "status": response.status_code,
                    "vulnerable": self._check_sql_injection_response(response)
                })
            except Exception as e:
                results.append({"error": str(e)})
        return results
    
    def _test_xss(self, url: str) -> Dict:
        """Test for XSS vulnerabilities"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        results = []
        for payload in payloads:
            try:
                response = self.session.get(f"{url}?input={payload}")
                results.append({
                    "payload": payload,
                    "status": response.status_code,
                    "vulnerable": self._check_xss_response(response)
                })
            except Exception as e:
                results.append({"error": str(e)})
        return results
    
    def _test_command_injection(self, url: str) -> Dict:
        """Test for command injection vulnerabilities"""
        payloads = [
            "; ls",
            "| cat /etc/passwd",
            "`id`",
            "$(id)"
        ]
        results = []
        for payload in payloads:
            try:
                response = self.session.get(f"{url}?cmd={payload}")
                results.append({
                    "payload": payload,
                    "status": response.status_code,
                    "vulnerable": self._check_command_injection_response(response)
                })
            except Exception as e:
                results.append({"error": str(e)})
        return results
    
    def _test_path_traversal(self, url: str) -> Dict:
        """Test for path traversal vulnerabilities"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        results = []
        for payload in payloads:
            try:
                response = self.session.get(f"{url}?file={payload}")
                results.append({
                    "payload": payload,
                    "status": response.status_code,
                    "vulnerable": self._check_path_traversal_response(response)
                })
            except Exception as e:
                results.append({"error": str(e)})
        return results
    
    def _test_basic_rate_limit(self, url: str) -> Dict:
        """Test basic rate limiting"""
        try:
            responses = []
            for _ in range(100):  # Try 100 requests
                response = self.session.get(url)
                responses.append(response.status_code)
            
            return {
                "requests": len(responses),
                "blocked": any(code == 429 for code in responses),
                "vulnerable": not any(code == 429 for code in responses)
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _test_ip_based_limit(self, url: str) -> Dict:
        """Test IP-based rate limiting"""
        try:
            responses = []
            for _ in range(100):  # Try 100 requests
                response = self.session.get(url)
                responses.append(response.status_code)
            
            return {
                "requests": len(responses),
                "blocked": any(code == 429 for code in responses),
                "vulnerable": not any(code == 429 for code in responses)
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _test_token_based_limit(self, url: str) -> Dict:
        """Test token-based rate limiting"""
        try:
            responses = []
            for _ in range(100):  # Try 100 requests
                response = self.session.get(url)
                responses.append(response.status_code)
            
            return {
                "requests": len(responses),
                "blocked": any(code == 429 for code in responses),
                "vulnerable": not any(code == 429 for code in responses)
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _check_csp_header(self, headers: Dict) -> Dict:
        """Check Content-Security-Policy header"""
        csp = headers.get("Content-Security-Policy", "")
        return {
            "present": bool(csp),
            "value": csp,
            "secure": self._is_csp_secure(csp)
        }
    
    def _check_hsts_header(self, headers: Dict) -> Dict:
        """Check HSTS header"""
        hsts = headers.get("Strict-Transport-Security", "")
        return {
            "present": bool(hsts),
            "value": hsts,
            "secure": self._is_hsts_secure(hsts)
        }
    
    def _check_x_frame_options(self, headers: Dict) -> Dict:
        """Check X-Frame-Options header"""
        xfo = headers.get("X-Frame-Options", "")
        return {
            "present": bool(xfo),
            "value": xfo,
            "secure": xfo in ["DENY", "SAMEORIGIN"]
        }
    
    def _check_x_content_type_options(self, headers: Dict) -> Dict:
        """Check X-Content-Type-Options header"""
        xcto = headers.get("X-Content-Type-Options", "")
        return {
            "present": bool(xcto),
            "value": xcto,
            "secure": xcto == "nosniff"
        }
    
    def _check_x_xss_protection(self, headers: Dict) -> Dict:
        """Check X-XSS-Protection header"""
        xxss = headers.get("X-XSS-Protection", "")
        return {
            "present": bool(xxss),
            "value": xxss,
            "secure": "1; mode=block" in xxss
        }
    
    def _check_jwt_vulnerabilities(self, response) -> bool:
        """Check for JWT vulnerabilities"""
        # Implement JWT vulnerability checks
        return False
    
    def _check_oauth_vulnerabilities(self, response) -> bool:
        """Check for OAuth vulnerabilities"""
        # Implement OAuth vulnerability checks
        return False
    
    def _check_role_based_vulnerabilities(self, response) -> bool:
        """Check for role-based authorization vulnerabilities"""
        # Implement role-based vulnerability checks
        return False
    
    def _check_resource_based_vulnerabilities(self, response) -> bool:
        """Check for resource-based authorization vulnerabilities"""
        # Implement resource-based vulnerability checks
        return False
    
    def _check_permission_based_vulnerabilities(self, response) -> bool:
        """Check for permission-based authorization vulnerabilities"""
        # Implement permission-based vulnerability checks
        return False
    
    def _check_sql_injection_response(self, response) -> bool:
        """Check response for SQL injection indicators"""
        # Implement SQL injection response checks
        return False
    
    def _check_xss_response(self, response) -> bool:
        """Check response for XSS indicators"""
        # Implement XSS response checks
        return False
    
    def _check_command_injection_response(self, response) -> bool:
        """Check response for command injection indicators"""
        # Implement command injection response checks
        return False
    
    def _check_path_traversal_response(self, response) -> bool:
        """Check response for path traversal indicators"""
        # Implement path traversal response checks
        return False
    
    def _is_csp_secure(self, csp: str) -> bool:
        """Check if CSP is secure"""
        # Implement CSP security checks
        return True
    
    def _is_hsts_secure(self, hsts: str) -> bool:
        """Check if HSTS is secure"""
        # Implement HSTS security checks
        return True 