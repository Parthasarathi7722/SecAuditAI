from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class BaseScanner(ABC):
    """Base class for all security scanners."""
    
    def __init__(self):
        self.name = self.__class__.__name__.lower().replace('scanner', '')
        self.description = ""
        self.supported_targets = []
        self.supported_frameworks = {}
        self._load_checks()
    
    @abstractmethod
    def _load_checks(self) -> None:
        """Load security checks for the scanner."""
        pass
    
    @abstractmethod
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Perform security scan on the target.
        
        Args:
            target: Path or identifier of the target to scan
            **kwargs: Additional scanner-specific parameters
            
        Returns:
            Dict containing scan results and findings
        """
        pass
    
    def _validate_target(self, target: str) -> bool:
        """Validate if the target is supported by the scanner."""
        if not self.supported_targets:
            return True
        return target in self.supported_targets
    
    def _validate_framework(self, framework: str) -> bool:
        """Validate if the compliance framework is supported."""
        if not self.supported_frameworks:
            return True
        return framework in self.supported_frameworks
    
    def _format_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Format findings into a standardized format."""
        return {
            "scanner": self.name,
            "description": self.description,
            "findings": findings,
            "summary": self._generate_summary(findings)
        }
    
    def _generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics from findings."""
        total = len(findings)
        high = len([f for f in findings if f.get("severity") == "high"])
        medium = len([f for f in findings if f.get("severity") == "medium"])
        low = len([f for f in findings if f.get("severity") == "low"])
        
        return {
            "total_findings": total,
            "high_severity": high,
            "medium_severity": medium,
            "low_severity": low,
            "risk_score": self._calculate_risk_score(high, medium, low)
        }
    
    def _calculate_risk_score(self, high: int, medium: int, low: int) -> float:
        """Calculate overall risk score based on findings."""
        return (high * 1.0 + medium * 0.5 + low * 0.1) / max(1, high + medium + low) 