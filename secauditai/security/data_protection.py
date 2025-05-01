#!/usr/bin/env python3
"""
Data Protection System
"""

import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import logging
from typing import Dict, Optional, Union, List
import hashlib
import re

class DataProtection:
    def __init__(
        self,
        encryption_key: Optional[str] = None,
        algorithm: str = "AES-256-GCM",
        salt: Optional[bytes] = None
    ):
        """
        Initialize data protection system
        
        Args:
            encryption_key: Optional encryption key
            algorithm: Encryption algorithm (AES-256-GCM, ChaCha20-Poly1305)
            salt: Optional salt for key derivation
        """
        self.algorithm = algorithm
        self.salt = salt or os.urandom(16)
        self.encryption_key = self._derive_key(encryption_key)
        self.logger = logging.getLogger(__name__)
    
    def _derive_key(self, key: Optional[str]) -> bytes:
        """Derive encryption key using PBKDF2"""
        if key is None:
            key = Fernet.generate_key()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(key.encode()))
    
    def encrypt(self, data: Union[str, Dict, bytes]) -> Dict:
        """
        Encrypt data
        
        Args:
            data: Data to encrypt (string, dict, or bytes)
            
        Returns:
            Dictionary containing encrypted data and metadata
        """
        if isinstance(data, dict):
            data = json.dumps(data).encode()
        elif isinstance(data, str):
            data = data.encode()
        
        # Generate nonce
        nonce = os.urandom(12)
        
        # Create cipher
        if self.algorithm == "AES-256-GCM":
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(nonce),
                backend=default_backend()
            )
        elif self.algorithm == "ChaCha20-Poly1305":
            cipher = Cipher(
                algorithms.ChaCha20(self.encryption_key, nonce),
                modes.Poly1305(),
                backend=default_backend()
            )
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
        
        # Encrypt data
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        
        # Get authentication tag
        tag = encryptor.tag if hasattr(encryptor, 'tag') else None
        
        return {
            "data": base64.b64encode(encrypted).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode() if tag else None,
            "algorithm": self.algorithm,
            "salt": base64.b64encode(self.salt).decode()
        }
    
    def decrypt(self, encrypted_data: Dict) -> Union[str, Dict, bytes]:
        """
        Decrypt data
        
        Args:
            encrypted_data: Dictionary containing encrypted data and metadata
            
        Returns:
            Decrypted data
        """
        # Extract components
        data = base64.b64decode(encrypted_data["data"])
        nonce = base64.b64decode(encrypted_data["nonce"])
        tag = base64.b64decode(encrypted_data["tag"]) if encrypted_data.get("tag") else None
        
        # Create cipher
        if encrypted_data["algorithm"] == "AES-256-GCM":
            cipher = Cipher(
                algorithms.AES(self.encryption_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
        elif encrypted_data["algorithm"] == "ChaCha20-Poly1305":
            cipher = Cipher(
                algorithms.ChaCha20(self.encryption_key, nonce),
                modes.Poly1305(),
                backend=default_backend()
            )
        else:
            raise ValueError(f"Unsupported algorithm: {encrypted_data['algorithm']}")
        
        # Decrypt data
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()
        
        # Try to parse as JSON
        try:
            return json.loads(decrypted)
        except json.JSONDecodeError:
            return decrypted.decode()
    
    def hash_data(self, data: Union[str, bytes], algorithm: str = "sha256") -> str:
        """
        Hash data
        
        Args:
            data: Data to hash
            algorithm: Hash algorithm (sha256, sha512, blake2b)
            
        Returns:
            Hexadecimal hash string
        """
        if isinstance(data, str):
            data = data.encode()
        
        if algorithm == "sha256":
            return hashlib.sha256(data).hexdigest()
        elif algorithm == "sha512":
            return hashlib.sha512(data).hexdigest()
        elif algorithm == "blake2b":
            return hashlib.blake2b(data).hexdigest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    def sanitize_data(self, data: Union[str, Dict, List]) -> Union[str, Dict, List]:
        """
        Sanitize data by removing sensitive information
        
        Args:
            data: Data to sanitize
            
        Returns:
            Sanitized data
        """
        if isinstance(data, str):
            # Remove potential sensitive patterns
            patterns = [
                r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # Phone numbers
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email addresses
                r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',  # Credit card numbers
                r'\b\d{3}[- ]?\d{2}[- ]?\d{4}\b',  # SSN
            ]
            
            for pattern in patterns:
                data = re.sub(pattern, '[REDACTED]', data)
            
            return data
        
        elif isinstance(data, dict):
            # Recursively sanitize dictionary
            return {k: self.sanitize_data(v) for k, v in data.items()}
        
        elif isinstance(data, list):
            # Recursively sanitize list
            return [self.sanitize_data(item) for item in data]
        
        else:
            return data
    
    def secure_logging(self, message: str, level: str = "INFO") -> None:
        """
        Securely log message with sensitive data redaction
        
        Args:
            message: Log message
            level: Log level (INFO, WARNING, ERROR, etc.)
        """
        # Sanitize message
        sanitized = self.sanitize_data(message)
        
        # Log with appropriate level
        if level.upper() == "INFO":
            self.logger.info(sanitized)
        elif level.upper() == "WARNING":
            self.logger.warning(sanitized)
        elif level.upper() == "ERROR":
            self.logger.error(sanitized)
        elif level.upper() == "DEBUG":
            self.logger.debug(sanitized)
        else:
            self.logger.info(sanitized) 