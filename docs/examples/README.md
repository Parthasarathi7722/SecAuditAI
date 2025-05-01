# SecAuditAI Examples

This directory contains example scripts demonstrating how to use SecAuditAI's features.

## Basic Usage

`basic_usage.py` demonstrates the fundamental features of SecAuditAI:
- Initialization of core components
- Basic credential management
- Simple access control
- Basic data protection
- Simple logging
- Basic configuration management
- Basic security scanning and reporting

## Advanced Usage

`advanced_usage.py` demonstrates more complex use cases:
- Advanced configuration options
- Multiple credential backends
- Custom roles and permissions
- Multiple encryption algorithms
- Structured logging with multiple handlers
- Environment variable configuration
- Bulk operations
- Async operations
- Continuous monitoring
- Advanced compliance reporting

## Running the Examples

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure the environment:
```bash
cp config.example.yaml config.yaml
# Edit config.yaml with your settings
```

3. Run the examples:
```bash
# Basic usage
python docs/examples/basic_usage.py

# Advanced usage
python docs/examples/advanced_usage.py
```

## Example Configuration

Before running the examples, make sure to update the following in your `config.yaml`:

```yaml
api:
  key: "your-api-key"
  base_url: "https://api.secauditai.com"

security:
  encryption_key: "your-encryption-key"
  jwt_secret: "your-jwt-secret"
  hmac_key: "your-hmac-key"

credentials:
  backend: "local"  # or "vault", "aws_secrets", "azure_keyvault"
  vault:
    url: "https://vault.example.com"
    token: "your-vault-token"
```

## Security Considerations

1. Never commit actual credentials or sensitive data
2. Use environment variables for sensitive values
3. Rotate keys and credentials regularly
4. Follow the principle of least privilege
5. Monitor and audit all security events

## Troubleshooting

If you encounter issues:

1. Check the log files for errors
2. Verify your configuration
3. Ensure all dependencies are installed
4. Check network connectivity
5. Verify permissions and access control

## Additional Resources

- [API Documentation](api.md)
- [User Guide](user_guide.md)
- [Troubleshooting Guide](troubleshooting.md)
- [Security Best Practices](security.md) 