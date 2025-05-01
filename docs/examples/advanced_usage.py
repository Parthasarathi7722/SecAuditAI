#!/usr/bin/env python3
"""
Advanced Usage Example for SecAuditAI
"""

from secauditai import SecAuditAI
from secauditai.security import (
    CredentialManager,
    AccessControl,
    DataProtection,
    SecureLogger,
    SecureConfig
)
import asyncio
from datetime import datetime, timedelta

async def main():
    # Initialize with advanced configuration
    client = SecAuditAI(
        api_key="your-api-key",
        config_file="config.yaml",
        timeout=60,
        retries=3
    )

    # Initialize with Vault backend
    credential_manager = CredentialManager(
        backend="vault",
        rotation_interval="24h",
        vault_config={
            "url": "https://vault.example.com",
            "token": "your-vault-token"
        }
    )

    # Initialize with custom roles and permissions
    access_control = AccessControl(
        roles=["admin", "auditor", "user", "operator"],
        permissions={
            "admin": ["*"],
            "auditor": ["read:*", "scan:*", "report:*", "audit:*"],
            "operator": ["scan:own", "report:own", "monitor:*"],
            "user": ["read:own", "scan:own"]
        },
        jwt_secret="your-jwt-secret",
        session_timeout="8h"
    )

    # Initialize with multiple encryption algorithms
    data_protection = DataProtection(
        encryption_key="your-encryption-key",
        algorithm="AES-256-GCM",
        salt="your-salt"
    )

    # Initialize with multiple handlers
    logger = SecureLogger(
        name="secauditai",
        log_file="app.log",
        level="DEBUG",
        handlers=[
            {
                "type": "file",
                "filename": "app.log",
                "max_bytes": 10485760,
                "backup_count": 5
            },
            {
                "type": "syslog",
                "address": "/dev/log"
            }
        ]
    )

    # Initialize with environment variables
    config = SecureConfig(
        config_path="config.yaml",
        encryption_key="your-encryption-key",
        env_prefix="SECAUDITAI_"
    )

    # Example: Store multiple credentials
    credentials = {
        "api_key": {
            "value": "your-api-key",
            "metadata": {"type": "api", "owner": "admin"}
        },
        "database": {
            "value": {
                "host": "localhost",
                "port": 5432,
                "username": "admin",
                "password": "secret"
            },
            "metadata": {"type": "database", "owner": "admin"}
        }
    }

    for name, cred in credentials.items():
        credential_manager.store_credential(
            name=name,
            credential=cred["value"],
            metadata=cred["metadata"]
        )

    # Example: Create token with custom claims
    token = access_control.create_token(
        user_id="user1",
        roles=["admin", "operator"],
        additional_claims={
            "email": "user@example.com",
            "department": "security",
            "permissions": ["scan:full", "report:generate"]
        }
    )

    # Example: Bulk encryption
    sensitive_data = [
        {"username": "admin", "password": "secret1"},
        {"username": "user", "password": "secret2"},
        {"username": "operator", "password": "secret3"}
    ]

    encrypted_data = [
        data_protection.encrypt(item)
        for item in sensitive_data
    ]

    # Example: Structured logging
    logger.info(
        "Security scan started",
        extra={
            "target": "example.com",
            "scan_type": "full",
            "timestamp": datetime.utcnow().isoformat(),
            "user": "admin",
            "metadata": {
                "environment": "production",
                "priority": "high"
            }
        }
    )

    # Example: Configuration management
    config.set("api.timeout", 60)
    config.set("logging.level", "DEBUG")
    config.set_secret("database.password", "new-password")
    config.rotate_key()

    # Example: Async security scan
    async def scan_targets(targets):
        tasks = [
            client.scan(target=target, scan_type="full")
            for target in targets
        ]
        return await asyncio.gather(*tasks)

    targets = ["example.com", "api.example.com", "admin.example.com"]
    results = await scan_targets(targets)

    # Example: Continuous monitoring
    async def monitor_security():
        while True:
            events = await client.monitor(
                interval="5m",
                alerts=True,
                filters={
                    "severity": ["high", "critical"],
                    "type": ["vulnerability", "breach"]
                }
            )
            
            for event in events:
                logger.warning(
                    "Security event detected",
                    extra=event
                )
            
            await asyncio.sleep(300)  # 5 minutes

    # Example: Compliance reporting
    frameworks = ["pci-dss", "hipaa", "gdpr"]
    reports = {}
    
    for framework in frameworks:
        report = await client.generate_report(
            framework=framework,
            format="pdf",
            template="detailed",
            filters={
                "date_range": {
                    "start": (datetime.utcnow() - timedelta(days=30)).isoformat(),
                    "end": datetime.utcnow().isoformat()
                },
                "severity": ["high", "critical"]
            }
        )
        reports[framework] = report

if __name__ == "__main__":
    asyncio.run(main()) 