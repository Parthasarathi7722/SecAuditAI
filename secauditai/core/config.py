import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from functools import lru_cache

logger = logging.getLogger(__name__)

@dataclass
class Config:
    """Configuration class for SecAuditAI."""
    
    # Default configuration values
    default_config: Dict[str, Any] = field(default_factory=lambda: {
        "general": {
            "log_level": "INFO",
            "output_dir": "~/.secauditai/reports",
            "cache_dir": "~/.secauditai/cache"
        },
        "scanners": {
            "code": {
                "enabled_languages": ["python", "javascript", "java"],
                "max_file_size": 10485760,  # 10MB
                "exclude_patterns": ["venv/", "node_modules/", ".git/"]
            },
            "sbom": {
                "enabled": True,
                "vulnerability_check": True,
                "license_check": True
            },
            "cloud": {
                "aws": {
                    "enabled": True,
                    "regions": ["us-east-1", "us-west-2"],
                    "max_results": 1000
                },
                "azure": {
                    "enabled": True,
                    "subscriptions": [],
                    "max_results": 1000
                },
                "gcp": {
                    "enabled": True,
                    "projects": [],
                    "max_results": 1000
                }
            }
        },
        "monitoring": {
            "enabled": False,
            "interval": 300,  # 5 minutes
            "notifications": {
                "slack": {
                    "enabled": False,
                    "webhook_url": ""
                },
                "email": {
                    "enabled": False,
                    "smtp_server": "",
                    "smtp_port": 587,
                    "username": "",
                    "password": ""
                }
            }
        },
        "api": {
            "enabled": False,
            "host": "localhost",
            "port": 8000,
            "auth_token": ""
        }
    })
    
    def __init__(self):
        self.config_dir = Path(os.path.expanduser("~/.secauditai"))
        self.config_file = self.config_dir / "config.yaml"
        self._ensure_config_dir()
        self._load_config()
    
    def _ensure_config_dir(self) -> None:
        """Ensure configuration directory exists."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        if not self.config_file.exists():
            self._save_config(self.default_config)
    
    def _load_config(self) -> None:
        """Load configuration from file."""
        try:
            with open(self.config_file, 'r') as f:
                self.config = yaml.safe_load(f) or self.default_config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            self.config = self.default_config
    
    def _save_config(self, config: Dict[str, Any]) -> None:
        """Save configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                yaml.safe_dump(config, f, default_flow_style=False)
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key."""
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value by key."""
        keys = key.split('.')
        config = self.config
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value
        self._save_config(self.config)
    
    def reset(self) -> None:
        """Reset configuration to defaults."""
        self.config = self.default_config
        self._save_config(self.config)
    
    @lru_cache(maxsize=1)
    def get_scanner_config(self, scanner_name: str) -> Dict[str, Any]:
        """Get configuration for specific scanner."""
        return self.get(f"scanners.{scanner_name}", {})
    
    def get_monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring configuration."""
        return self.get("monitoring", {})
    
    def get_api_config(self) -> Dict[str, Any]:
        """Get API configuration."""
        return self.get("api", {}) 