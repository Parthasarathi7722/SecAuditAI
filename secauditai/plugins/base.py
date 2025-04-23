#!/usr/bin/env python3
"""
Base scanner module providing the foundation for all scanner plugins.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class BaseScanner(ABC):
    """Abstract base class for all scanner plugins."""
    
    def __init__(self):
        self.name: str = ""
        self.description: str = ""
        self.supported_providers: list = []
        
    @abstractmethod
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Perform a security scan on the specified target.
        
        Args:
            target: The target to scan (e.g., file path, URL, cloud resource)
            **kwargs: Additional scanner-specific arguments
            
        Returns:
            Dict containing scan results and findings
        """
        pass
        
    def validate_target(self, target: str) -> bool:
        """
        Validate if the target is supported by this scanner.
        
        Args:
            target: The target to validate
            
        Returns:
            bool: True if target is supported, False otherwise
        """
        return target in self.supported_providers
        
    def get_metadata(self) -> Dict[str, Any]:
        """
        Get scanner metadata.
        
        Returns:
            Dict containing scanner name, description, and supported providers
        """
        return {
            "name": self.name,
            "description": self.description,
            "supported_providers": self.supported_providers
        } 