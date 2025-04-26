# SecAuditAI

SecAuditAI is a comprehensive security auditing tool that leverages AI to perform automated security assessments across various domains including cloud infrastructure, code analysis, and compliance checks.

## Features

- **AI-Powered Code Analysis**: Advanced static code analysis using Tree-sitter and custom vulnerability detection models
- **Cloud Infrastructure Scanning**: Comprehensive security assessment for AWS, Azure, and GCP environments
- **SBOM Vulnerability Detection**: Automated Software Bill of Materials analysis and vulnerability scanning
- **CIS Benchmark Checks**: Automated Center for Internet Security benchmark compliance verification
- **Modular Plugin Architecture**: Extensible design allowing easy addition of new scanners and analyzers
- **Comprehensive Reporting**: Detailed security reports with actionable insights and remediation steps
- **Real-time Analysis**: Continuous monitoring and alerting capabilities
- **Compliance Framework Support**: Built-in support for major compliance frameworks (CIS, PCI, HIPAA, NIST, ISO27001)
- **Zero-Day Vulnerability Detection**: Advanced AI models for detecting unknown vulnerabilities
- **Container Security**: Comprehensive container image scanning and runtime security monitoring
- **Infrastructure as Code Security**: Automated security checks for Terraform, CloudFormation, and ARM templates
- **API Security Testing**: Automated API security testing and vulnerability detection
- **Custom Rule Engine**: Support for custom security rules and policies
- **Integration Support**: Slack notifications and webhook integrations for alerts

## Installation

### Using Docker (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/Parthasarathi7722/SecAuditAI.git
cd SecAuditAI
```

2. Create a `.env` file with your cloud credentials:
```bash
# AWS Credentials
AWS_ACCESS_KEY_ID=your_aws_key
AWS_SECRET_ACCESS_KEY=your_aws_secret
AWS_DEFAULT_REGION=your_region

# Azure Credentials
AZURE_CLIENT_ID=your_azure_client_id
AZURE_CLIENT_SECRET=your_azure_secret
AZURE_TENANT_ID=your_azure_tenant_id

# GCP Credentials
GOOGLE_APPLICATION_CREDENTIALS=/app/credentials.json
```

3. Build and run the Docker container:
```bash
docker-compose build
docker-compose up
```

### Manual Installation

1. Clone the repository:
```bash
git clone https://github.com/Parthasarathi7722/SecAuditAI.git
cd SecAuditAI
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

4. Install binary tools:
```bash
./scripts/install_tools.sh
```

5. Install the package:
```bash
pip install -e .
```

## Quick Start

### Basic Usage

```bash
# Scan a code repository
secauditai scan code /path/to/repo

# Scan cloud infrastructure
secauditai scan aws --profile default
secauditai scan azure --subscription-id <id>
secauditai scan gcp --project-id <id>

# Generate SBOM
secauditai sbom generate /path/to/project

# Run compliance check
secauditai compliance check aws --framework cis
```

### Docker Usage

```bash
# Basic code scan
docker run -v $(pwd):/app secauditai scan code /app/path/to/repo

# Cloud infrastructure scan
docker run -v $(pwd):/app \
  -e AWS_ACCESS_KEY_ID=your_key \
  -e AWS_SECRET_ACCESS_KEY=your_secret \
  secauditai scan aws --profile default

# Container security scan
docker run -v /var/run/docker.sock:/var/run/docker.sock \
  secauditai container scan local_image:tag
```

## Documentation

- [Model Training Guide](docs/model_training.md): Detailed instructions for training and fine-tuning AI models
- [API Reference](docs/api.md): Complete API documentation
- [Examples](docs/examples/): Usage examples and tutorials
- [Troubleshooting Guide](docs/troubleshooting.md): Common issues and solutions

## Development

### Using Docker

1. Start the development container:
```bash
docker-compose up -d
```

2. Access the container shell:
```bash
docker-compose exec secauditai bash
```

3. Run tests:
```bash
pytest tests/
```

### Manual Development

1. Activate the virtual environment:
```bash
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Run tests:
```bash
pytest tests/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests:
```bash
docker-compose run secauditai pytest tests/
```
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Roadmap

- [ ] Enhanced AI model training pipeline
- [ ] Additional cloud provider support
- [ ] Advanced container runtime security
- [ ] Real-time security monitoring dashboard
- [ ] Integration with CI/CD pipelines
- [ ] Custom rule engine improvements
- [ ] Advanced reporting capabilities
- [ ] Performance optimizations
- [ ] Additional compliance frameworks
- [ ] Enhanced API security testing
- [ ] Machine learning model improvements
- [ ] Documentation improvements
- [ ] Community contributions
