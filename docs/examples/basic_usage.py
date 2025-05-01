#!/usr/bin/env python3
"""
Basic Usage Example for SecAuditAI
"""

from secauditai import SecAuditAI
from secauditai.security import CredentialManager, AccessControl, DataProtection, SecureLogger, SecureConfig

def main():
    # Initialize SecAuditAI client
    client = SecAuditAI(
        api_key="your-api-key",
        config_file="config.yaml"
    )

    # Initialize security components
    credential_manager = CredentialManager(
        backend="local",
        rotation_interval="24h"
    )

    access_control = AccessControl(
        roles=["admin", "auditor", "user"],
        permissions={
            "admin": ["*"],
            "auditor": ["read:*", "scan:*", "report:*"],
            "user": ["read:own", "scan:own"]
        },
        jwt_secret="your-jwt-secret"
    )

    data_protection = DataProtection(
        encryption_key="your-encryption-key"
    )

    logger = SecureLogger(
        name="secauditai",
        log_file="app.log",
        level="INFO"
    )

    config = SecureConfig(
        config_path="config.yaml",
        encryption_key="your-encryption-key"
    )

    # Example: Store credentials
    credential_manager.store_credential(
        name="api_key",
        credential="your-api-key",
        metadata={"type": "api", "owner": "admin"}
    )

    # Example: Create access token
    token = access_control.create_token(
        user_id="user1",
        roles=["admin"],
        additional_claims={"email": "user@example.com"}
    )

    # Example: Encrypt sensitive data
    encrypted_data = data_protection.encrypt({
        "username": "admin",
        "password": "secret"
    })

    # Example: Log security event
    logger.info(
        "Security scan completed",
        extra={
            "target": "example.com",
            "status": "success",
            "findings": 5
        }
    )

    # Example: Get configuration
    api_key = config.get("api.key")
    log_level = config.get("logging.level")

    # Example: Run security scan
    results = client.scan(
        target="example.com",
        scan_type="full"
    )

    # Example: Generate compliance report
    report = client.generate_report(
        framework="pci-dss",
        format="pdf"
    )

    # Example: Monitor security events
    events = client.monitor(
        interval="5m",
        alerts=True
    )

if __name__ == "__main__":
    main() 