#!/usr/bin/env python3
"""
Secure Credential Management System
"""

import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime, timedelta
import logging
from typing import Dict, Optional, Union

class CredentialManager:
    def __init__(
        self,
        backend: str = "local",
        rotation_interval: str = "24h",
        encryption_key: Optional[str] = None
    ):
        """
        Initialize credential manager
        
        Args:
            backend: Storage backend ("local", "vault", "aws_secrets", "azure_keyvault")
            rotation_interval: Credential rotation interval (e.g., "24h", "7d")
            encryption_key: Optional encryption key for local storage
        """
        self.backend = backend
        self.rotation_interval = self._parse_interval(rotation_interval)
        self.encryption_key = encryption_key or self._generate_key()
        self.fernet = Fernet(self.encryption_key)
        self.logger = logging.getLogger(__name__)
        
        # Initialize backend
        self._init_backend()
    
    def _parse_interval(self, interval: str) -> timedelta:
        """Parse time interval string into timedelta"""
        value = int(interval[:-1])
        unit = interval[-1]
        
        if unit == 'h':
            return timedelta(hours=value)
        elif unit == 'd':
            return timedelta(days=value)
        elif unit == 'm':
            return timedelta(minutes=value)
        else:
            raise ValueError(f"Invalid interval unit: {unit}")
    
    def _generate_key(self) -> bytes:
        """Generate encryption key"""
        return Fernet.generate_key()
    
    def _init_backend(self):
        """Initialize storage backend"""
        if self.backend == "local":
            self._init_local_backend()
        elif self.backend == "vault":
            self._init_vault_backend()
        elif self.backend == "aws_secrets":
            self._init_aws_backend()
        elif self.backend == "azure_keyvault":
            self._init_azure_backend()
        else:
            raise ValueError(f"Unsupported backend: {self.backend}")
    
    def _init_local_backend(self):
        """Initialize local file-based storage"""
        self.storage_path = os.path.expanduser("~/.secauditai/credentials")
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
    
    def _init_vault_backend(self):
        """Initialize HashiCorp Vault backend"""
        import hvac
        self.vault_client = hvac.Client()
    
    def _init_aws_backend(self):
        """Initialize AWS Secrets Manager backend"""
        import boto3
        self.secrets_client = boto3.client('secretsmanager')
    
    def _init_azure_backend(self):
        """Initialize Azure Key Vault backend"""
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient
        credential = DefaultAzureCredential()
        self.keyvault_client = SecretClient(
            vault_url="https://your-keyvault.vault.azure.net/",
            credential=credential
        )
    
    def store_credential(
        self,
        name: str,
        credential: Union[str, Dict],
        metadata: Optional[Dict] = None
    ) -> None:
        """
        Store a credential
        
        Args:
            name: Credential name
            credential: Credential value (string or dict)
            metadata: Optional metadata
        """
        if isinstance(credential, dict):
            credential = json.dumps(credential)
        
        # Encrypt credential
        encrypted = self.fernet.encrypt(credential.encode())
        
        # Store with metadata
        data = {
            "credential": encrypted.decode(),
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + self.rotation_interval).isoformat(),
            "metadata": metadata or {}
        }
        
        if self.backend == "local":
            self._store_local(name, data)
        elif self.backend == "vault":
            self._store_vault(name, data)
        elif self.backend == "aws_secrets":
            self._store_aws(name, data)
        elif self.backend == "azure_keyvault":
            self._store_azure(name, data)
    
    def get_credential(self, name: str) -> Union[str, Dict]:
        """
        Retrieve a credential
        
        Args:
            name: Credential name
            
        Returns:
            Decrypted credential value
        """
        if self.backend == "local":
            data = self._get_local(name)
        elif self.backend == "vault":
            data = self._get_vault(name)
        elif self.backend == "aws_secrets":
            data = self._get_aws(name)
        elif self.backend == "azure_keyvault":
            data = self._get_azure(name)
        
        # Check expiration
        expires_at = datetime.fromisoformat(data["expires_at"])
        if datetime.utcnow() > expires_at:
            self.logger.warning(f"Credential {name} has expired")
        
        # Decrypt and return
        decrypted = self.fernet.decrypt(data["credential"].encode())
        try:
            return json.loads(decrypted)
        except json.JSONDecodeError:
            return decrypted.decode()
    
    def rotate_credentials(self) -> None:
        """Rotate all credentials"""
        if self.backend == "local":
            self._rotate_local()
        elif self.backend == "vault":
            self._rotate_vault()
        elif self.backend == "aws_secrets":
            self._rotate_aws()
        elif self.backend == "azure_keyvault":
            self._rotate_azure()
    
    def _store_local(self, name: str, data: Dict) -> None:
        """Store credential in local file"""
        with open(self.storage_path, 'a') as f:
            f.write(f"{name}:{json.dumps(data)}\n")
    
    def _get_local(self, name: str) -> Dict:
        """Get credential from local file"""
        with open(self.storage_path, 'r') as f:
            for line in f:
                stored_name, data = line.strip().split(':', 1)
                if stored_name == name:
                    return json.loads(data)
        raise KeyError(f"Credential not found: {name}")
    
    def _rotate_local(self) -> None:
        """Rotate local credentials"""
        # Implementation for local credential rotation
        pass
    
    def _store_vault(self, name: str, data: Dict) -> None:
        """Store credential in Vault"""
        self.vault_client.secrets.kv.v2.create_or_update_secret(
            path=name,
            secret=data
        )
    
    def _get_vault(self, name: str) -> Dict:
        """Get credential from Vault"""
        response = self.vault_client.secrets.kv.v2.read_secret_version(
            path=name
        )
        return response['data']['data']
    
    def _rotate_vault(self) -> None:
        """Rotate Vault credentials"""
        # Implementation for Vault credential rotation
        pass
    
    def _store_aws(self, name: str, data: Dict) -> None:
        """Store credential in AWS Secrets Manager"""
        self.secrets_client.create_secret(
            Name=name,
            SecretString=json.dumps(data)
        )
    
    def _get_aws(self, name: str) -> Dict:
        """Get credential from AWS Secrets Manager"""
        response = self.secrets_client.get_secret_value(
            SecretId=name
        )
        return json.loads(response['SecretString'])
    
    def _rotate_aws(self) -> None:
        """Rotate AWS credentials"""
        # Implementation for AWS credential rotation
        pass
    
    def _store_azure(self, name: str, data: Dict) -> None:
        """Store credential in Azure Key Vault"""
        self.keyvault_client.set_secret(
            name=name,
            value=json.dumps(data)
        )
    
    def _get_azure(self, name: str) -> Dict:
        """Get credential from Azure Key Vault"""
        secret = self.keyvault_client.get_secret(name)
        return json.loads(secret.value)
    
    def _rotate_azure(self) -> None:
        """Rotate Azure credentials"""
        # Implementation for Azure credential rotation
        pass 