#!/usr/bin/env python3
"""
Secure Configuration Management System
"""

import os
import json
import yaml
import logging
from typing import Dict, Optional, Union, Any
from cryptography.fernet import Fernet
import base64
from pathlib import Path
import hashlib

class SecureConfig:
    def __init__(
        self,
        config_path: str,
        encryption_key: Optional[str] = None,
        env_prefix: str = "SECAUDITAI_"
    ):
        """
        Initialize secure configuration manager
        
        Args:
            config_path: Path to configuration file
            encryption_key: Optional encryption key
            env_prefix: Environment variable prefix
        """
        self.config_path = Path(config_path)
        self.encryption_key = encryption_key or Fernet.generate_key()
        self.fernet = Fernet(self.encryption_key)
        self.env_prefix = env_prefix
        self.logger = logging.getLogger(__name__)
        
        # Load configuration
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        """Load configuration from file"""
        if not self.config_path.exists():
            self.logger.warning(f"Configuration file not found: {self.config_path}")
            return {}
        
        # Read file based on extension
        if self.config_path.suffix == '.json':
            with open(self.config_path, 'r') as f:
                config = json.load(f)
        elif self.config_path.suffix in ['.yaml', '.yml']:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
        else:
            raise ValueError(f"Unsupported configuration format: {self.config_path.suffix}")
        
        # Decrypt sensitive values
        return self._decrypt_config(config)
    
    def _save_config(self) -> None:
        """Save configuration to file"""
        # Create directory if it doesn't exist
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Encrypt sensitive values
        encrypted_config = self._encrypt_config(self.config)
        
        # Write file based on extension
        if self.config_path.suffix == '.json':
            with open(self.config_path, 'w') as f:
                json.dump(encrypted_config, f, indent=2)
        elif self.config_path.suffix in ['.yaml', '.yml']:
            with open(self.config_path, 'w') as f:
                yaml.safe_dump(encrypted_config, f)
        else:
            raise ValueError(f"Unsupported configuration format: {self.config_path.suffix}")
    
    def _encrypt_value(self, value: str) -> str:
        """Encrypt configuration value"""
        return self.fernet.encrypt(value.encode()).decode()
    
    def _decrypt_value(self, encrypted_value: str) -> str:
        """Decrypt configuration value"""
        return self.fernet.decrypt(encrypted_value.encode()).decode()
    
    def _encrypt_config(self, config: Dict) -> Dict:
        """Encrypt sensitive configuration values"""
        encrypted = {}
        for key, value in config.items():
            if isinstance(value, dict):
                encrypted[key] = self._encrypt_config(value)
            elif isinstance(value, str) and key.startswith('secret_'):
                encrypted[key] = self._encrypt_value(value)
            else:
                encrypted[key] = value
        return encrypted
    
    def _decrypt_config(self, config: Dict) -> Dict:
        """Decrypt sensitive configuration values"""
        decrypted = {}
        for key, value in config.items():
            if isinstance(value, dict):
                decrypted[key] = self._decrypt_config(value)
            elif isinstance(value, str) and key.startswith('secret_'):
                decrypted[key] = self._decrypt_value(value)
            else:
                decrypted[key] = value
        return decrypted
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        # Check environment variables first
        env_key = f"{self.env_prefix}{key.upper()}"
        if env_key in os.environ:
            return os.environ[env_key]
        
        # Check configuration file
        value = self.config
        for part in key.split('.'):
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default
        return value
    
    def set(self, key: str, value: Any, save: bool = True) -> None:
        """
        Set configuration value
        
        Args:
            key: Configuration key
            value: Configuration value
            save: Whether to save configuration to file
        """
        # Update configuration
        parts = key.split('.')
        current = self.config
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        current[parts[-1]] = value
        
        # Save configuration if requested
        if save:
            self._save_config()
    
    def delete(self, key: str, save: bool = True) -> None:
        """
        Delete configuration value
        
        Args:
            key: Configuration key
            save: Whether to save configuration to file
        """
        # Delete from configuration
        parts = key.split('.')
        current = self.config
        for part in parts[:-1]:
            if part not in current:
                return
            current = current[part]
        if parts[-1] in current:
            del current[parts[-1]]
        
        # Save configuration if requested
        if save:
            self._save_config()
    
    def get_secret(self, key: str, default: Any = None) -> Optional[str]:
        """
        Get secret value
        
        Args:
            key: Secret key
            default: Default value if key not found
            
        Returns:
            Secret value
        """
        return self.get(f"secret_{key}", default)
    
    def set_secret(self, key: str, value: str, save: bool = True) -> None:
        """
        Set secret value
        
        Args:
            key: Secret key
            value: Secret value
            save: Whether to save configuration to file
        """
        self.set(f"secret_{key}", value, save)
    
    def delete_secret(self, key: str, save: bool = True) -> None:
        """
        Delete secret value
        
        Args:
            key: Secret key
            save: Whether to save configuration to file
        """
        self.delete(f"secret_{key}", save)
    
    def rotate_key(self, new_key: Optional[str] = None) -> None:
        """
        Rotate encryption key
        
        Args:
            new_key: Optional new encryption key
        """
        # Generate new key if not provided
        if new_key is None:
            new_key = Fernet.generate_key()
        
        # Create new Fernet instance
        new_fernet = Fernet(new_key)
        
        # Re-encrypt all secrets
        for key, value in self.config.items():
            if isinstance(value, dict):
                self._rotate_key_recursive(value, new_fernet)
            elif isinstance(value, str) and key.startswith('secret_'):
                self.config[key] = new_fernet.encrypt(
                    self.fernet.decrypt(value.encode())
                ).decode()
        
        # Update key
        self.encryption_key = new_key
        self.fernet = new_fernet
        
        # Save configuration
        self._save_config()
    
    def _rotate_key_recursive(self, config: Dict, new_fernet: Fernet) -> None:
        """Recursively rotate encryption key"""
        for key, value in config.items():
            if isinstance(value, dict):
                self._rotate_key_recursive(value, new_fernet)
            elif isinstance(value, str) and key.startswith('secret_'):
                config[key] = new_fernet.encrypt(
                    self.fernet.decrypt(value.encode())
                ).decode()
    
    def validate(self) -> bool:
        """
        Validate configuration
        
        Returns:
            True if configuration is valid, False otherwise
        """
        try:
            # Check required fields
            required_fields = [
                'api_key',
                'database_url',
                'log_level'
            ]
            
            for field in required_fields:
                if not self.get(field):
                    self.logger.error(f"Missing required field: {field}")
                    return False
            
            # Validate database URL
            db_url = self.get('database_url')
            if not db_url.startswith(('postgresql://', 'mysql://', 'sqlite://')):
                self.logger.error("Invalid database URL format")
                return False
            
            # Validate log level
            log_level = self.get('log_level')
            valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
            if log_level not in valid_levels:
                self.logger.error(f"Invalid log level: {log_level}")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Configuration validation failed: {e}")
            return False
    
    def get_hash(self) -> str:
        """
        Get configuration hash
        
        Returns:
            SHA-256 hash of configuration
        """
        config_str = json.dumps(self.config, sort_keys=True)
        return hashlib.sha256(config_str.encode()).hexdigest()
    
    def reload(self) -> None:
        """Reload configuration from file"""
        self.config = self._load_config()
    
    def reset(self) -> None:
        """Reset configuration to default values"""
        self.config = {}
        self._save_config() 