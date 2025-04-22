"""
Configuration management for SecAuditAI.
"""
import os
from pathlib import Path
from typing import Dict, Any, Optional
import yaml
from pydantic import BaseModel, Field

class CloudConfig(BaseModel):
    """Cloud provider configuration."""
    aws_profile: Optional[str] = None
    aws_region: Optional[str] = None
    azure_subscription: Optional[str] = None
    azure_resource_group: Optional[str] = None
    gcp_project: Optional[str] = None
    gcp_zone: Optional[str] = None

class AIConfig(BaseModel):
    """AI model configuration."""
    model_name: str = "codellama"
    model_path: Optional[str] = None
    cache_dir: str = "~/.secauditai/cache"
    max_tokens: int = 2048
    temperature: float = 0.7

class ScannerConfig(BaseModel):
    """Scanner configuration."""
    enabled_scanners: list[str] = Field(default_factory=list)
    custom_checks_path: Optional[str] = None
    output_format: str = "json"
    output_dir: str = "~/.secauditai/results"

class Config(BaseModel):
    """Main configuration model."""
    cloud: CloudConfig = Field(default_factory=CloudConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)

class ConfigManager:
    """Manages configuration loading and saving."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or os.path.expanduser("~/.secauditai/config.yaml")
        self.config_dir = os.path.dirname(self.config_path)
        self._ensure_config_dir()
        self.config = self._load_config()

    def _ensure_config_dir(self) -> None:
        """Ensure configuration directory exists."""
        os.makedirs(self.config_dir, exist_ok=True)

    def _load_config(self) -> Config:
        """Load configuration from file."""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                config_data = yaml.safe_load(f) or {}
            return Config(**config_data)
        return Config()

    def save_config(self) -> None:
        """Save configuration to file."""
        config_data = self.config.dict()
        with open(self.config_path, 'w') as f:
            yaml.dump(config_data, f, default_flow_style=False)

    def update_config(self, updates: Dict[str, Any]) -> None:
        """Update configuration with new values."""
        for key, value in updates.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
        self.save_config()

    def get_config(self) -> Config:
        """Get current configuration."""
        return self.config 