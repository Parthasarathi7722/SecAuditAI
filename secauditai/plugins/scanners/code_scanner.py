"""
Code security scanner plugin.
"""
import os
from typing import Dict, Any, List
from pathlib import Path
import tree_sitter
from tree_sitter import Language, Parser
import re
from .. import ScannerPlugin

class CodeScanner(ScannerPlugin):
    """Code security scanner implementation."""
    
    def __init__(self):
        self.parser = Parser()
        self.languages = {}
        self._load_languages()
        self.checks = self._load_checks()

    def _load_languages(self) -> None:
        """Load Tree-sitter language parsers."""
        languages = {
            'python': 'tree-sitter-python',
            'javascript': 'tree-sitter-javascript',
            'java': 'tree-sitter-java',
            'go': 'tree-sitter-go'
        }
        
        # Create build directory
        build_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'build')
        os.makedirs(build_dir, exist_ok=True)
        
        # Build language library
        language_lib = os.path.join(build_dir, 'languages.so')
        Language.build_library(
            language_lib,
            [
                'tree-sitter-python',
                'tree-sitter-javascript',
                'tree-sitter-java',
                'tree-sitter-go'
            ]
        )
        
        # Load languages
        for lang, repo in languages.items():
            try:
                self.languages[lang] = Language(language_lib, lang)
            except Exception as e:
                print(f"Error loading {lang} parser: {str(e)}")

    def _load_checks(self) -> List[Dict[str, Any]]:
        """Load code security checks."""
        return [
            {
                "id": "code-001",
                "name": "Hardcoded Secrets",
                "description": "Check for hardcoded credentials and secrets",
                "severity": "high"
            },
            {
                "id": "code-002",
                "name": "SQL Injection",
                "description": "Check for potential SQL injection vulnerabilities",
                "severity": "high"
            },
            {
                "id": "code-003",
                "name": "XSS Vulnerability",
                "description": "Check for potential XSS vulnerabilities",
                "severity": "high"
            },
            {
                "id": "code-004",
                "name": "Broken Access Control",
                "description": "Check for broken access control vulnerabilities",
                "severity": "high"
            },
            {
                "id": "code-005",
                "name": "CSRF Vulnerability",
                "description": "Check for CSRF protection",
                "severity": "high"
            },
            {
                "id": "code-006",
                "name": "File Inclusion",
                "description": "Check for file inclusion vulnerabilities",
                "severity": "high"
            }
        ]

    def _check_hardcoded_secrets(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Check for hardcoded secrets in code."""
        findings = []
        
        # Common patterns for secrets
        secret_patterns = [
            r'password\s*=\s*[\'"][^\'"]+[\'"]',
            r'api_key\s*=\s*[\'"][^\'"]+[\'"]',
            r'secret\s*=\s*[\'"][^\'"]+[\'"]',
            r'token\s*=\s*[\'"][^\'"]+[\'"]',
            r'aws_access_key_id\s*=\s*[\'"][^\'"]+[\'"]',
            r'aws_secret_access_key\s*=\s*[\'"][^\'"]+[\'"]',
            r'private_key\s*=\s*[\'"][^\'"]+[\'"]',
            r'certificate\s*=\s*[\'"][^\'"]+[\'"]'
        ]
        
        for pattern in secret_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "check_id": "code-001",
                    "resource": f"Line {code.count('\n', 0, match.start()) + 1}",
                    "status": "failed",
                    "message": "Potential hardcoded secret found",
                    "severity": "high",
                    "recommendation": "Use environment variables or secure secret management"
                })
        
        return findings

    def _check_sql_injection(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Check for SQL injection vulnerabilities."""
        findings = []
        
        # SQL injection patterns
        sql_patterns = [
            r'execute\s*\([^)]*\+',
            r'exec\s*\([^)]*\+',
            r'query\s*\([^)]*\+',
            r'raw\s*\([^)]*\+',
            r'format\s*\([^)]*\+',
            r'f\s*"[^"]*\{[^}]*\}.*"'
        ]
        
        for pattern in sql_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "check_id": "code-002",
                    "resource": f"Line {code.count('\n', 0, match.start()) + 1}",
                    "status": "failed",
                    "message": "Potential SQL injection vulnerability",
                    "severity": "high",
                    "recommendation": "Use parameterized queries or prepared statements"
                })
        
        return findings

    def _check_xss(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Check for XSS vulnerabilities."""
        findings = []
        
        # XSS patterns
        xss_patterns = [
            r'innerHTML\s*=\s*[^;]+',
            r'document\.write\s*\([^)]+\)',
            r'eval\s*\([^)]+\)',
            r'setTimeout\s*\([^)]+\)',
            r'setInterval\s*\([^)]+\)',
            r'location\s*=\s*[^;]+',
            r'location\.href\s*=\s*[^;]+'
        ]
        
        for pattern in xss_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "check_id": "code-003",
                    "resource": f"Line {code.count('\n', 0, match.start()) + 1}",
                    "status": "failed",
                    "message": "Potential XSS vulnerability",
                    "severity": "high",
                    "recommendation": "Use proper output encoding and sanitization"
                })
        
        return findings

    def _check_broken_access_control(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Check for broken access control vulnerabilities."""
        findings = []
        
        # Broken access control patterns
        access_patterns = [
            r'is_admin\s*=\s*True',
            r'is_admin\s*=\s*true',
            r'role\s*=\s*[\'"]admin[\'"]',
            r'permission\s*=\s*[\'"]all[\'"]',
            r'bypass\s*=\s*True',
            r'bypass\s*=\s*true'
        ]
        
        for pattern in access_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "check_id": "code-004",
                    "resource": f"Line {code.count('\n', 0, match.start()) + 1}",
                    "status": "failed",
                    "message": "Potential broken access control vulnerability",
                    "severity": "high",
                    "recommendation": "Implement proper access control checks"
                })
        
        return findings

    def _check_csrf(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Check for CSRF protection."""
        findings = []
        
        # CSRF patterns
        csrf_patterns = [
            r'@csrf_exempt',
            r'csrf_exempt\s*\(',
            r'disable_csrf\s*=\s*True',
            r'disable_csrf\s*=\s*true'
        ]
        
        for pattern in csrf_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "check_id": "code-005",
                    "resource": f"Line {code.count('\n', 0, match.start()) + 1}",
                    "status": "failed",
                    "message": "CSRF protection disabled",
                    "severity": "high",
                    "recommendation": "Enable CSRF protection"
                })
        
        return findings

    def _check_file_inclusion(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Check for file inclusion vulnerabilities."""
        findings = []
        
        # File inclusion patterns
        file_patterns = [
            r'include\s*\([^)]+\)',
            r'require\s*\([^)]+\)',
            r'require_once\s*\([^)]+\)',
            r'include_once\s*\([^)]+\)',
            r'fopen\s*\([^)]+\)',
            r'file_get_contents\s*\([^)]+\)'
        ]
        
        for pattern in file_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "check_id": "code-006",
                    "resource": f"Line {code.count('\n', 0, match.start()) + 1}",
                    "status": "failed",
                    "message": "Potential file inclusion vulnerability",
                    "severity": "high",
                    "recommendation": "Validate file paths and use allowlists"
                })
        
        return findings

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform code security scan."""
        path = kwargs.get('path')
        language = kwargs.get('language', 'python')
        
        if not path or not os.path.exists(path):
            return {
                "scanner": self.get_name(),
                "target": target,
                "findings": [{
                    "check_id": "code-000",
                    "resource": path,
                    "status": "error",
                    "message": "Invalid path provided"
                }],
                "summary": {
                    "total": 1,
                    "failed": 0,
                    "passed": 0,
                    "error": 1
                }
            }
        
        try:
            with open(path, 'r') as f:
                code = f.read()
            
            # Set language parser
            if language in self.languages:
                self.parser.set_language(self.languages[language])
            
            findings = []
            findings.extend(self._check_hardcoded_secrets(code, language))
            findings.extend(self._check_sql_injection(code, language))
            findings.extend(self._check_xss(code, language))
            findings.extend(self._check_broken_access_control(code, language))
            findings.extend(self._check_csrf(code, language))
            findings.extend(self._check_file_inclusion(code, language))
            
            return {
                "scanner": self.get_name(),
                "target": target,
                "findings": findings,
                "summary": {
                    "total": len(findings),
                    "failed": len([f for f in findings if f['status'] == 'failed']),
                    "passed": len([f for f in findings if f['status'] == 'passed']),
                    "error": len([f for f in findings if f['status'] == 'error'])
                }
            }
            
        except Exception as e:
            return {
                "scanner": self.get_name(),
                "target": target,
                "findings": [{
                    "check_id": "code-000",
                    "resource": path,
                    "status": "error",
                    "message": f"Error scanning file: {str(e)}"
                }],
                "summary": {
                    "total": 1,
                    "failed": 0,
                    "passed": 0,
                    "error": 1
                }
            }

    def get_name(self) -> str:
        """Get scanner name."""
        return "code"

    def get_description(self) -> str:
        """Get scanner description."""
        return "Source code security scanner" 