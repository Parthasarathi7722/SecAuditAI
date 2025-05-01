# SecAuditAI

A comprehensive security audit and compliance automation tool powered by AI, designed to help organizations maintain robust security postures and meet compliance requirements.

## Features

- **Automated Security Scanning**
  - Code analysis and vulnerability detection
  - Infrastructure security assessment
  - Network security scanning
  - Container security analysis
  - Cloud security posture management
  - **Infrastructure as Code (IaC) Security**
    - Terraform security scanning
    - CloudFormation template analysis
    - Kubernetes manifest validation
    - Ansible playbook security checks
    - Multi-cloud IaC security assessment

- **AI-Powered Analysis**
  - Intelligent vulnerability prioritization
  - Automated remediation suggestions
  - Pattern recognition for security issues
  - Risk assessment and scoring
  - Threat intelligence integration

- **Security Management**
  - Secure credential management with multiple backends
  - Role-based access control (RBAC)
  - Encrypted logging and audit trails
  - Secure configuration management
  - Automated security reporting

## Underlying Tools

SecAuditAI integrates with several industry-standard security tools:

- **Static Analysis**
  - Bandit (Python security)
  - Semgrep (Multi-language analysis)
  - SonarQube (Code quality and security)
  - Checkov (Infrastructure as Code)

- **Dynamic Analysis**
  - OWASP ZAP (Web application security)
  - Nmap (Network scanning)
  - Nikto (Web server scanning)
  - OpenVAS (Vulnerability assessment)

- **Container Security**
  - Trivy (Container vulnerability scanning)
  - Clair (Container image analysis)
  - Anchore (Container security platform)

- **Cloud Security**
  - Prowler (AWS security assessment)
  - Scout Suite (Multi-cloud security auditing)
  - CloudSploit (Cloud security monitoring)

- **Infrastructure as Code Security**
  - Checkov (Terraform, CloudFormation, Kubernetes)
  - TFLint (Terraform best practices)
  - cfn-nag (CloudFormation security)
  - kube-bench (Kubernetes CIS benchmarks)
  - kube-hunter (Kubernetes penetration testing)
  - ansible-lint (Ansible security)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/secauditai.git
cd secauditai
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure the application:
```bash
cp config.example.yaml config.yaml
# Edit config.yaml with your settings
```

## Configuration

The application can be configured using:

1. Environment variables (prefixed with `SECAUDITAI_`)
2. Configuration file (`config.yaml` or `config.json`)
3. Command-line arguments

### Required Configuration

- `api_key`: Your SecAuditAI API key
- `database_url`: Database connection URL
- `log_level`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

### Security Configuration

- `encryption_key`: Encryption key for sensitive data
- `jwt_secret`: Secret key for JWT token generation
- `hmac_key`: Key for HMAC verification

## Usage Examples

### Infrastructure as Code Security

```bash
# Scan Terraform configurations
secauditai scan --target terraform --path /path/to/terraform

# Scan CloudFormation templates
secauditai scan --target cloudformation --path /path/to/templates

# Scan Kubernetes manifests
secauditai scan --target kubernetes --path /path/to/manifests

# Scan Ansible playbooks
secauditai scan --target ansible --path /path/to/playbooks

# Multi-IaC scan
secauditai scan --target iac --providers terraform,cloudformation,kubernetes

# Generate IaC security report
secauditai report --format csv --output iac_security.csv
```

### Basic Security Scan

```bash
# Run a basic security scan
secauditai scan --target example.com --type basic

# Scan with specific checks
secauditai scan --target example.com --checks sql-injection,xss,csrf

# Generate CSV report
secauditai scan --target example.com --format csv --output report.csv
```

### Infrastructure Scanning

```bash
# Scan AWS infrastructure
secauditai scan --target aws --region us-east-1 --profile default

# Scan Kubernetes cluster
secauditai scan --target k8s --context my-cluster --namespace default

# Scan Docker containers
secauditai scan --target docker --image nginx:latest
```

### Code Analysis

```bash
# Analyze Python code
secauditai scan --target code --language python --path /path/to/code

# Analyze JavaScript code
secauditai scan --target code --language javascript --path /path/to/code

# Analyze multiple languages
secauditai scan --target code --languages python,javascript,go --path /path/to/code
```


Example CSV report structure:
```csv
id,severity,category,title,description,location,remediation,status,last_updated
VULN-001,High,Security,SQL Injection,SQL injection vulnerability in login form,/app/login.php,Use prepared statements,Open,2023-05-01
VULN-002,Medium,Security,XSS,Cross-site scripting in search form,/app/search.php,Implement input validation,Fixed,2023-05-02
```

## Python API Examples

### Basic Usage

```python
from secauditai import SecAuditAI

# Initialize client
client = SecAuditAI(api_key="your-api-key")

# Run security scan
results = client.scan("example.com")

# Generate compliance report
report = client.generate_report("pci-dss")

# Monitor security events
events = client.monitor(alerts=True)
```

### Advanced Usage

```python
from secauditai import SecAuditAI
import asyncio

async def main():
    client = SecAuditAI(api_key="your-api-key")
    
    # Run multiple scans concurrently
    targets = ["example.com", "api.example.com"]
    results = await asyncio.gather(*[
        client.scan(target, scan_type="full")
        for target in targets
    ])
    
    # Generate CSV report
    await client.generate_report(
        format="csv",
        output="report.csv",
        include=["vulnerabilities", "compliance", "recommendations"]
    )

asyncio.run(main())
```

## Security Features

### Credential Management

- Secure storage of API keys and credentials
- Automatic credential rotation
- Support for multiple backends:
  - Local encrypted storage
  - HashiCorp Vault
  - AWS Secrets Manager
  - Azure Key Vault

### Access Control

- Role-based access control (RBAC)
- JWT-based authentication
- Permission-based authorization
- Session management and timeout

### Data Protection

- Encryption of sensitive data
- Secure logging with redaction
- HMAC verification
- Data sanitization

### Secure Configuration

- Encrypted configuration storage
- Environment variable support
- Configuration validation
- Key rotation

## Development

### Testing

```bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=secauditai

# Run specific test
pytest tests/test_scanner.py
```

### Code Style

```bash
# Format code
black .

# Sort imports
isort .

# Lint code
flake8
```

### Documentation

```bash
# Build documentation
cd docs
make html
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please open an issue in the GitHub repository or contact support@secauditai.com.

## Security

If you discover a security vulnerability, please report it to security@secauditai.com.