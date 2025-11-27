"""
Plugin system for SecAuditAI.
"""
from typing import Dict, Any, List, Type, Optional, Iterable
from abc import ABC, abstractmethod
from ..config import ConfigManager

class ScannerPlugin(ABC):
    """Base class for scanner plugins."""
    
    @abstractmethod
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform security scan."""
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """Get scanner name."""
        pass
    
    @abstractmethod
    def get_description(self) -> str:
        """Get scanner description."""
        pass

class PluginManager:
    """Manages scanner plugins."""
    
    def __init__(self, config: Optional[Any] = None):
        # Accept an optional config object to improve integration with other modules
        self.config = config or ConfigManager().get_config()
        self.scanners: Dict[str, ScannerPlugin] = {}
        self._load_plugins()

    def _load_plugins(self) -> None:
        """Load all available scanner plugins."""
        from .scanners.aws_scanner import AWSScanner
        from .scanners.azure_scanner import AzureScanner
        from .scanners.code_scanner import CodeScanner
        from .scanners.sbom_scanner import SBOMScanner
        
        # Register scanners
        self.register_plugin(AWSScanner())
        self.register_plugin(AzureScanner())
        self.register_plugin(CodeScanner())
        self.register_plugin(SBOMScanner())

    def register_plugin(self, plugin: ScannerPlugin) -> None:
        """Register a scanner plugin."""
        self.scanners[plugin.get_name()] = plugin

    def get_plugin(self, name: str) -> Optional[ScannerPlugin]:
        """Get a scanner plugin by name."""
        return self.scanners.get(name)

    def get_scanners(self) -> List[ScannerPlugin]:
        """Return a list of registered scanner instances."""
        return list(self.scanners.values())

    def iter_scanners(self) -> Iterable[ScannerPlugin]:
        """Iterate over registered scanners without extra allocations."""
        return self.scanners.values()

    def list_plugins(self) -> List[Dict[str, str]]:
        """List all available scanner plugins."""
        return [
            {
                "name": plugin.get_name(),
                "description": plugin.get_description()
            }
            for plugin in self.scanners.values()
        ] 