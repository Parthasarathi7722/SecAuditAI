Here’s a cleaned-up, syntax-correct version of your `code_scanner.py` with the merge damage fixed, duplicate defs removed, and logic preserved:

```python
"""
Code security scanner plugin.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Match

from .. import ScannerPlugin

Findings = List[Dict[str, Any]]


class CodeScanner(ScannerPlugin):
    """Code security scanner implementation."""

    def __init__(self):
        self.languages = self._load_languages()
        self.checks = self._load_checks()

    @staticmethod
    def _line_number(code: str, match: Match[str]) -> int:
        """Return the 1-based line number for a regex match."""
        return code.count("\n", 0, match.start()) + 1

    def _load_languages(self) -> Dict[str, Dict[str, Any]]:
        """Return metadata about supported languages."""
        languages = {
            "python": {"extensions": [".py"]},
            "javascript": {"extensions": [".js", ".jsx"]},
            "java": {"extensions": [".java"]},
            "go": {"extensions": [".go"]},
        }
        return languages

    def _load_checks(self) -> Dict[str, Dict[str, Any]]:
        """Load code security checks."""
        return {
            "hardcoded_secrets": {
                "id": "code-001",
                "name": "Hardcoded Secrets",
                "description": "Check for hardcoded credentials and secrets",
                "severity": "high",
            },
            "sql_injection": {
                "id": "code-002",
                "name": "SQL Injection",
                "description": "Check for potential SQL injection vulnerabilities",
                "severity": "high",
            },
            "xss": {
                "id": "code-003",
                "name": "XSS Vulnerability",
                "description": "Check for potential XSS vulnerabilities",
                "severity": "high",
            },
            "broken_access_control": {
                "id": "code-004",
                "name": "Broken Access Control",
                "description": "Check for broken access control vulnerabilities",
                "severity": "high",
            },
            "csrf": {
                "id": "code-005",
                "name": "CSRF Vulnerability",
                "description": "Check for CSRF protection",
                "severity": "high",
            },
            "file_inclusion": {
                "id": "code-006",
                "name": "File Inclusion",
                "description": "Check for file inclusion vulnerabilities",
                "severity": "high",
            },
        }

    @staticmethod
    def _resource(file_path: Optional[Path]) -> str:
        """Return a stable resource string for a finding."""
        return str(file_path or Path("<memory>"))

    def _check_hardcoded_secrets(
        self, code: str, language: str, file_path: Optional[Path] = None
    ) -> List[Dict[str, Any]]:
        """Check for hardcoded secrets in code."""
        findings: Findings = []
        resource = self._resource(file_path)

        # Common patterns for secrets
        secret_patterns = [
            r'password\s*=\s*[\'"][^\'"]+[\'"]',
            r'api_key\s*=\s*[\'"][^\'"]+[\'"]',
            r'secret\s*=\s*[\'"][^\'"]+[\'"]',
            r'token\s*=\s*[\'"][^\'"]+[\'"]',
            r'aws_access_key_id\s*=\s*[\'"][^\'"]+[\'"]',
            r'aws_secret_access_key\s*=\s*[\'"][^\'"]+[\'"]',
            r'private_key\s*=\s*[\'"][^\'"]+[\'"]',
            r'certificate\s*=\s*[\'"][^\'"]+[\'"]',
            r'ghp_[A-Za-z0-9]{10,}',
        ]

        for pattern in secret_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                findings.append(
                    {
                        "check_id": "code-001",
                        "resource": f"{resource}:{self._line_number(code, match)}",
                        "status": "failed",
                        "message": "Potential hardcoded secret found",
                        "severity": "high",
                        "recommendation": "Use environment variables or secure secret management",
                    }
                )

        return findings

    def _check_sql_injection(
        self, code: str, language: str, file_path: Optional[Path] = None
    ) -> List[Dict[str, Any]]:
        """Check for SQL injection vulnerabilities."""
        findings: Findings = []
        resource = self._resource(file_path)

        # SQL injection patterns
        sql_patterns = [
            r'execute\s*\([^)]*\+',
            r'exec\s*\([^)]*\+',
            r'query\s*\([^)]*\+',
            r'query\s*\([^)]*\$\{[^}]+\}',
            r'raw\s*\([^)]*\+',
            r'format\s*\([^)]*\+',
            r'f\s*"[^"]*\{[^}]*\}.*"',
        ]

        for pattern in sql_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                findings.append(
                    {
                        "check_id": "code-002",
                        "resource": f"{resource}:{self._line_number(code, match)}",
                        "status": "failed",
                        "message": "Potential SQL injection vulnerability",
                        "severity": "high",
                        "recommendation": "Use parameterized queries or prepared statements",
                    }
                )

        return findings

    def _check_xss(
        self, code: str, language: str, file_path: Optional[Path] = None
    ) -> List[Dict[str, Any]]:
        """Check for XSS vulnerabilities."""
        findings: Findings = []
        resource = self._resource(file_path)

        # XSS patterns
        xss_patterns = [
            r'innerHTML\s*=\s*[^;]+',
            r'document\.write\s*\([^)]+\)',
            r'eval\s*\([^)]+\)',
            r'setTimeout\s*\([^)]+\)',
            r'setInterval\s*\([^)]+\)',
            r'location\s*=\s*[^;]+',
            r'location\.href\s*=\s*[^;]+',
        ]

        for pattern in xss_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                findings.append(
                    {
                        "check_id": "code-003",
                        "resource": f"{resource}:{self._line_number(code, match)}",
                        "status": "failed",
                        "message": "Potential XSS vulnerability",
                        "severity": "high",
                        "recommendation": "Use proper output encoding and sanitization",
                    }
                )

        return findings

    def _check_broken_access_control(
        self, code: str, language: str, file_path: Optional[Path] = None
    ) -> List[Dict[str, Any]]:
        """Check for broken access control vulnerabilities."""
        findings: Findings = []
        resource = self._resource(file_path)

        # Broken access control patterns
        access_patterns = [
            r'is_admin\s*=\s*True',
            r'is_admin\s*=\s*true',
            r'role\s*=\s*[\'"]admin[\'"]',
            r'permission\s*=\s*[\'"]all[\'"]',
            r'bypass\s*=\s*True',
            r'bypass\s*=\s*true',
        ]

        for pattern in access_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                findings.append(
                    {
                        "check_id": "code-004",
                        "resource": f"{resource}:{self._line_number(code, match)}",
                        "status": "failed",
                        "message": "Potential broken access control vulnerability",
                        "severity": "high",
                        "recommendation": "Implement proper access control checks",
                    }
                )

        return findings

    def _check_csrf(
        self, code: str, language: str, file_path: Optional[Path] = None
    ) -> List[Dict[str, Any]]:
        """Check for CSRF protection."""
        findings: Findings = []
        resource = self._resource(file_path)

        # CSRF patterns
        csrf_patterns = [
            r'@csrf_exempt',
            r'csrf_exempt\s*\(',
            r'disable_csrf\s*=\s*True',
            r'disable_csrf\s*=\s*true',
        ]

        for pattern in csrf_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                findings.append(
                    {
                        "check_id": "code-005",
                        "resource": f"{resource}:{self._line_number(code, match)}",
                        "status": "failed",
                        "message": "CSRF protection disabled",
                        "severity": "high",
                        "recommendation": "Enable CSRF protection",
                    }
                )

        return findings

    def _check_file_inclusion(
        self, code: str, language: str, file_path: Optional[Path] = None
    ) -> List[Dict[str, Any]]:
        """Check for file inclusion vulnerabilities."""
        findings: Findings = []
        resource = self._resource(file_path)

        # File inclusion patterns
        file_patterns = [
            r'include\s*\([^)]+\)',
            r'require\s*\([^)]+\)',
            r'require_once\s*\([^)]+\)',
            r'include_once\s*\([^)]+\)',
            r'fopen\s*\([^)]+\)',
            r'file_get_contents\s*\([^)]+\)',
        ]

        for pattern in file_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                findings.append(
                    {
                        "check_id": "code-006",
                        "resource": f"{resource}:{self._line_number(code, match)}",
                        "status": "failed",
                        "message": "Potential file inclusion vulnerability",
                        "severity": "high",
                        "recommendation": "Validate file paths and use allowlists",
                    }
                )

        return findings

    def _detect_language(self, file_path: Path) -> Optional[str]:
        """Infer language from file extension."""
        for language, metadata in self.languages.items():
            if any(str(file_path).endswith(ext) for ext in metadata["extensions"]):
                return language
        return None

    def _iter_source_files(
        self, target_path: Path, language: Optional[str]
    ) -> List[Tuple[Path, str]]:
        """Collect supported source files under the target."""
        if language and language not in self.languages:
            raise ValueError(f"Unsupported language: {language}")

        if target_path.is_file():
            detected = language or self._detect_language(target_path)
            if not detected:
                raise ValueError(f"Unsupported file type: {target_path.suffix}")
            return [(target_path, detected)]

        files: List[Tuple[Path, str]] = []
        target_languages = [language] if language else list(self.languages.keys())
        for lang in target_languages:
            for ext in self.languages[lang]["extensions"]:
                for file_path in target_path.rglob(f"*{ext}"):
                    files.append((file_path, lang))

        if not files:
            raise ValueError("No supported source files were found for scanning.")
        return files

    def _summarize_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics for findings."""
        summary = {
            "total_findings": len(findings),
            "high_severity": 0,
            "medium_severity": 0,
            "low_severity": 0,
        }
        for finding in findings:
            severity = finding.get("severity", "").lower()
            key = f"{severity}_severity"
            if key in summary:
                summary[key] += 1
        return summary

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform code security scan."""
        path = kwargs.get("path") or target
        requested_language = kwargs.get("language")

        if not path:
            raise ValueError("Path must be provided for code scanning.")

        target_path = Path(path)
        if not target_path.exists():
            raise ValueError(f"Invalid path provided: {path}")

        findings: Findings = []
        for file_path, language in self._iter_source_files(target_path, requested_language):
            code = file_path.read_text(encoding="utf-8", errors="ignore")
            findings.extend(self._check_hardcoded_secrets(code, language, file_path))
            findings.extend(self._check_sql_injection(code, language, file_path))
            findings.extend(self._check_xss(code, language, file_path))
            findings.extend(self._check_broken_access_control(code, language, file_path))
            findings.extend(self._check_csrf(code, language, file_path))
            findings.extend(self._check_file_inclusion(code, language, file_path))

        result = {
            "scanner": self.get_name(),
            "target": target,
            "findings": findings,
            "summary": self._summarize_findings(findings),
        }
        return result

    def get_name(self) -> str:
        """Get scanner name."""
        return "code"

    def get_description(self) -> str:
        """Get scanner description."""
        return "Source code security scanner"
```
