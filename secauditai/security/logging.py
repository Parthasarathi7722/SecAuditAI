#!/usr/bin/env python3
"""
Secure Logging System
"""

import logging
import logging.handlers
import os
import json
import datetime
from typing import Dict, Optional, Union
import hashlib
import hmac
from cryptography.fernet import Fernet
import sys

class SecureLogger:
    def __init__(
        self,
        name: str,
        log_file: str,
        level: int = logging.INFO,
        max_bytes: int = 10 * 1024 * 1024,  # 10MB
        backup_count: int = 5,
        encryption_key: Optional[str] = None,
        hmac_key: Optional[str] = None
    ):
        """
        Initialize secure logger
        
        Args:
            name: Logger name
            log_file: Path to log file
            level: Logging level
            max_bytes: Maximum log file size
            backup_count: Number of backup files to keep
            encryption_key: Optional encryption key
            hmac_key: Optional HMAC key
        """
        self.name = name
        self.log_file = log_file
        self.encryption_key = encryption_key or Fernet.generate_key()
        self.hmac_key = hmac_key or os.urandom(32)
        self.fernet = Fernet(self.encryption_key)
        
        # Create logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        # Create formatter
        self.formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Create rotating file handler
        self.handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        self.handler.setFormatter(self.formatter)
        self.logger.addHandler(self.handler)
        
        # Add console handler for errors
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.ERROR)
        console_handler.setFormatter(self.formatter)
        self.logger.addHandler(console_handler)
    
    def _encrypt(self, data: str) -> str:
        """Encrypt log data"""
        return self.fernet.encrypt(data.encode()).decode()
    
    def _decrypt(self, encrypted_data: str) -> str:
        """Decrypt log data"""
        return self.fernet.decrypt(encrypted_data.encode()).decode()
    
    def _generate_hmac(self, data: str) -> str:
        """Generate HMAC for data"""
        return hmac.new(
            self.hmac_key,
            data.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def _verify_hmac(self, data: str, hmac_value: str) -> bool:
        """Verify HMAC for data"""
        expected_hmac = self._generate_hmac(data)
        return hmac.compare_digest(expected_hmac, hmac_value)
    
    def _sanitize(self, data: Union[str, Dict]) -> str:
        """Sanitize sensitive data"""
        if isinstance(data, dict):
            data = json.dumps(data)
        
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
    
    def _format_log_entry(
        self,
        level: str,
        message: str,
        extra: Optional[Dict] = None
    ) -> str:
        """Format log entry with metadata"""
        entry = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "level": level,
            "message": self._sanitize(message),
            "extra": self._sanitize(extra) if extra else None
        }
        
        # Encrypt sensitive data
        encrypted = self._encrypt(json.dumps(entry))
        
        # Add HMAC
        hmac_value = self._generate_hmac(encrypted)
        
        return json.dumps({
            "data": encrypted,
            "hmac": hmac_value
        })
    
    def _parse_log_entry(self, entry: str) -> Dict:
        """Parse and verify log entry"""
        data = json.loads(entry)
        
        # Verify HMAC
        if not self._verify_hmac(data["data"], data["hmac"]):
            raise ValueError("Log entry HMAC verification failed")
        
        # Decrypt data
        decrypted = self._decrypt(data["data"])
        return json.loads(decrypted)
    
    def info(self, message: str, extra: Optional[Dict] = None) -> None:
        """Log info message"""
        entry = self._format_log_entry("INFO", message, extra)
        self.logger.info(entry)
    
    def warning(self, message: str, extra: Optional[Dict] = None) -> None:
        """Log warning message"""
        entry = self._format_log_entry("WARNING", message, extra)
        self.logger.warning(entry)
    
    def error(self, message: str, extra: Optional[Dict] = None) -> None:
        """Log error message"""
        entry = self._format_log_entry("ERROR", message, extra)
        self.logger.error(entry)
    
    def debug(self, message: str, extra: Optional[Dict] = None) -> None:
        """Log debug message"""
        entry = self._format_log_entry("DEBUG", message, extra)
        self.logger.debug(entry)
    
    def critical(self, message: str, extra: Optional[Dict] = None) -> None:
        """Log critical message"""
        entry = self._format_log_entry("CRITICAL", message, extra)
        self.logger.critical(entry)
    
    def read_logs(self, start_time: Optional[datetime.datetime] = None) -> List[Dict]:
        """
        Read and decrypt logs
        
        Args:
            start_time: Optional start time to filter logs
            
        Returns:
            List of decrypted log entries
        """
        entries = []
        
        with open(self.log_file, 'r') as f:
            for line in f:
                try:
                    entry = self._parse_log_entry(line.strip())
                    
                    # Filter by time if specified
                    if start_time:
                        entry_time = datetime.datetime.fromisoformat(entry["timestamp"])
                        if entry_time < start_time:
                            continue
                    
                    entries.append(entry)
                except (ValueError, json.JSONDecodeError) as e:
                    self.logger.error(f"Failed to parse log entry: {e}")
        
        return entries
    
    def rotate_logs(self) -> None:
        """Rotate log files"""
        self.handler.doRollover()
    
    def clear_logs(self) -> None:
        """Clear all log files"""
        self.handler.close()
        if os.path.exists(self.log_file):
            os.remove(self.log_file)
        self.handler = logging.handlers.RotatingFileHandler(
            self.log_file,
            maxBytes=self.handler.maxBytes,
            backupCount=self.handler.backupCount
        )
        self.handler.setFormatter(self.formatter)
        self.logger.addHandler(self.handler)
    
    def set_level(self, level: int) -> None:
        """Set logging level"""
        self.logger.setLevel(level)
    
    def add_handler(self, handler: logging.Handler) -> None:
        """Add additional log handler"""
        handler.setFormatter(self.formatter)
        self.logger.addHandler(handler)
    
    def remove_handler(self, handler: logging.Handler) -> None:
        """Remove log handler"""
        self.logger.removeHandler(handler) 