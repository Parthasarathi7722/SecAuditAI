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
- **Training Data Preparation**: Tools for preparing and validating training data for AI models

## Installation

### Using Docker (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/yourusername/SecAuditAI.git
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
git clone https://github.com/yourusername/SecAuditAI.git
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
# Install Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Prowler
pip install prowler-cloud
```

5. Install the package:
```bash
pip install -e .
```

## Tooling Details

### Security Scanning Tools

1. **Grype (Anchore)**
   - Vulnerability scanning for container images and filesystems
   - Supports multiple package formats
   - Continuous vulnerability database updates
   - Official Documentation: https://github.com/anchore/grype

2. **Syft (Anchore)**
   - Software Bill of Materials (SBOM) generation
   - Supports multiple package formats
   - Detailed dependency analysis
   - Official Documentation: https://github.com/anchore/syft

3. **Prowler**
   - AWS security best practices assessment
   - CIS benchmark checks
   - Multiple compliance frameworks
   - Official Documentation: https://github.com/prowler-cloud/prowler

4. **OpenSCAP**
   - Security compliance checking
   - Vulnerability scanning
   - Configuration assessment
   - Official Documentation: https://www.open-scap.org/

5. **InSpec**
   - Infrastructure compliance testing
   - Security policy enforcement
   - Multi-platform support
   - Official Documentation: https://www.inspec.io/

## Scanning Options

### Code Security Scanning

```bash
# Basic code scan
secauditai scan code /path/to/repo

# Scan with specific languages
secauditai scan code /path/to/repo --languages python,javascript

# Scan with custom rules
secauditai scan code /path/to/repo --rules custom_rules.yaml

# Generate detailed report
secauditai scan code /path/to/repo --output report.html
```

### Cloud Infrastructure Scanning

#### AWS
```bash
# Basic AWS scan
secauditai scan aws --profile default

# Scan specific services
secauditai scan aws --services ec2,s3,iam

# Scan with compliance framework
secauditai scan aws --compliance cis

# Generate detailed report
secauditai scan aws --output aws_report.html
```

#### Azure
```bash
# Basic Azure scan
secauditai scan azure --subscription-id <id>

# Scan specific resource groups
secauditai scan azure --resource-groups rg1,rg2

# Scan with compliance framework
secauditai scan azure --compliance nist

# Generate detailed report
secauditai scan azure --output azure_report.html
```

#### GCP
```bash
# Basic GCP scan
secauditai scan gcp --project-id <id>

# Scan specific services
secauditai scan gcp --services compute,storage,iam

# Scan with compliance framework
secauditai scan gcp --compliance iso27001

# Generate detailed report
secauditai scan gcp --output gcp_report.html
```

### Kubernetes Security

```bash
# Basic Kubernetes scan
secauditai scan k8s --context <context>

# Scan specific namespaces
secauditai scan k8s --namespaces default,kube-system

# Scan with compliance framework
secauditai scan k8s --compliance cis

# Generate detailed report
secauditai scan k8s --output k8s_report.html
```

### SBOM Analysis

```bash
# Generate SBOM
secauditai sbom generate /path/to/project

# Analyze SBOM for vulnerabilities
secauditai sbom analyze sbom.json

# Export SBOM in different formats
secauditai sbom export sbom.json --format spdx,cyclonedx

# Generate detailed report
secauditai sbom report sbom.json --output sbom_report.html
```

### Container Security

```bash
# Scan container image
secauditai container scan image:tag

# Scan container runtime
secauditai container scan runtime

# Scan with specific checks
secauditai container scan image:tag --checks vuln,config

# Generate detailed report
secauditai container scan image:tag --output container_report.html
```

### Compliance Checks

```bash
# Run CIS benchmark check
secauditai compliance check aws --framework cis

# Run PCI-DSS compliance check
secauditai compliance check azure --framework pci

# Run HIPAA compliance check
secauditai compliance check gcp --framework hipaa

# Generate compliance report
secauditai compliance report --framework cis --output compliance_report.html
```

## Report Generation

### Report Types

1. **HTML Reports**
   - Interactive dashboards
   - Detailed findings
   - Remediation steps
   - Export to PDF

2. **PDF Reports**
   - Executive summary
   - Technical details
   - Compliance status
   - Action items

3. **Markdown Reports**
   - Version control friendly
   - Easy to edit
   - GitHub compatible
   - Export to other formats

### Report Customization

```bash
# Generate HTML report
secauditai report generate scan_results.json --format html

# Generate PDF report
secauditai report generate scan_results.json --format pdf

# Generate markdown report
secauditai report generate scan_results.json --format markdown

# Customize report template
secauditai report generate scan_results.json --template custom_template.html
```

### Report Management

```bash
# List all reports
secauditai report list

# View specific report
secauditai report view report_id

# Delete report
secauditai report delete report_id

# Export report
secauditai report export report_id --format pdf
```

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

4. Run specific tests:
```bash
pytest tests/test_code_scanner.py
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

3. Run specific tests:
```bash
pytest tests/test_code_scanner.py
```

## Quick Start

```bash
# Scan a code repository
secauditai scan code /path/to/repo

# Scan AWS infrastructure
secauditai scan aws --profile default

# Scan Azure infrastructure
secauditai scan azure --subscription-id <id>

# Scan GCP infrastructure
secauditai scan gcp --project-id <id>

# Scan Kubernetes cluster
secauditai scan k8s --context <context>

# Generate SBOM
secauditai sbom generate /path/to/project

# Run compliance check
secauditai compliance check aws --framework cis

# Monitor for security issues
secauditai monitor start --config monitoring.yaml
```

## Usage

### Code Security Scanning

```bash
# Basic code scan
secauditai scan code /path/to/repo

# Scan with specific languages
secauditai scan code /path/to/repo --languages python,javascript

# Scan with custom rules
secauditai scan code /path/to/repo --rules custom_rules.yaml

# Generate detailed report
secauditai scan code /path/to/repo --output report.html
```

### Cloud Infrastructure Scanning

#### AWS
```bash
# Basic AWS scan
secauditai scan aws --profile default

# Scan specific services
secauditai scan aws --services ec2,s3,iam

# Scan with compliance framework
secauditai scan aws --compliance cis

# Generate detailed report
secauditai scan aws --output aws_report.html
```

#### Azure
```bash
# Basic Azure scan
secauditai scan azure --subscription-id <id>

# Scan specific resource groups
secauditai scan azure --resource-groups rg1,rg2

# Scan with compliance framework
secauditai scan azure --compliance nist

# Generate detailed report
secauditai scan azure --output azure_report.html
```

#### GCP
```bash
# Basic GCP scan
secauditai scan gcp --project-id <id>

# Scan specific services
secauditai scan gcp --services compute,storage,iam

# Scan with compliance framework
secauditai scan gcp --compliance iso27001

# Generate detailed report
secauditai scan gcp --output gcp_report.html
```

### Kubernetes Security

```bash
# Basic Kubernetes scan
secauditai scan k8s --context <context>

# Scan specific namespaces
secauditai scan k8s --namespaces default,kube-system

# Scan with compliance framework
secauditai scan k8s --compliance cis

# Generate detailed report
secauditai scan k8s --output k8s_report.html
```

### SBOM Analysis

```bash
# Generate SBOM
secauditai sbom generate /path/to/project

# Analyze SBOM for vulnerabilities
secauditai sbom analyze sbom.json

# Export SBOM in different formats
secauditai sbom export sbom.json --format spdx,cyclonedx

# Generate detailed report
secauditai sbom report sbom.json --output sbom_report.html
```

### Container Security

```bash
# Scan container image
secauditai container scan image:tag

# Scan container runtime
secauditai container scan runtime

# Scan with specific checks
secauditai container scan image:tag --checks vuln,config

# Generate detailed report
secauditai container scan image:tag --output container_report.html
```

### Compliance Checks

```bash
# Run CIS benchmark check
secauditai compliance check aws --framework cis

# Run PCI-DSS compliance check
secauditai compliance check azure --framework pci

# Run HIPAA compliance check
secauditai compliance check gcp --framework hipaa

# Generate compliance report
secauditai compliance report --framework cis --output compliance_report.html
```

### Report Generation

```bash
# Generate HTML report
secauditai report generate scan_results.json --format html

# Generate PDF report
secauditai report generate scan_results.json --format pdf

# Generate markdown report
secauditai report generate scan_results.json --format markdown

# Customize report template
secauditai report generate scan_results.json --template custom_template.html
```

### Report Management

```bash
# List all reports
secauditai report list

# View specific report
secauditai report view report_id

# Delete report
secauditai report delete report_id

# Export report
secauditai report export report_id --format pdf
```

### Configuration

```bash
# Initialize configuration
secauditai config init

# Set configuration value
secauditai config set key value

# Get configuration value
secauditai config get key

# List all configurations
secauditai config list

# Reset configuration
secauditai config reset
```

### Monitoring

```bash
# Start monitoring
secauditai monitor start --config monitoring.yaml

# Stop monitoring
secauditai monitor stop

# View monitoring status
secauditai monitor status

# Configure alerts
secauditai monitor config alerts --slack webhook_url
```

## Advanced Usage

### Custom Rules

Create custom security rules in YAML format:

```yaml
rules:
  - id: custom-001
    name: Custom Security Check
    description: Check for custom security requirement
    severity: high
    language: python
    pattern: |
      def unsafe_function():
        pass
```

### API Integration

```python
from secauditai import SecAuditAI

# Initialize client
client = SecAuditAI()

# Scan code
results = client.scan_code("/path/to/repo")

# Scan cloud infrastructure
results = client.scan_cloud("aws", profile="default")

# Generate report
report = client.generate_report(results, format="html")
```

### Webhook Integration

Configure webhooks in `config.yaml`:

```yaml
webhooks:
  - url: https://api.example.com/webhook
    events:
      - scan_completed
      - high_severity_finding
```

## Common Examples

### Basic Code Scan
```bash
secauditai scan code /path/to/repo --languages python,javascript --output report.html
```

### Cloud Infrastructure Scan
```bash
secauditai scan aws --profile default --services ec2,s3,iam --compliance cis
```

### Kubernetes Security Scan
```bash
secauditai scan k8s --context production --namespaces default,kube-system
```

### SBOM Generation and Analysis
```bash
secauditai sbom generate /path/to/project --output sbom.json
secauditai sbom analyze sbom.json --output vulnerabilities.html
```

### Container Security Scan
```bash
secauditai container scan myapp:latest --checks vuln,config --output container_report.html
```

### Compliance Check
```bash
secauditai compliance check aws --framework cis --output compliance_report.html
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests:
```bash
docker-compose run secauditai pytest tests/
```
5. Submit a pull request

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