# SecAuditAI

A powerful CLI security audit tool that combines AI-powered code analysis, cloud infrastructure scanning, SBOM vulnerability detection, and CIS benchmark checks.

## Features

### AI-Powered Code Analysis
Detect security vulnerabilities in source code using advanced LLM models
- **Powered by**:
  - CodeBERT (Microsoft Research) for semantic code analysis
  - Tree-sitter for language parsing
  - Custom-trained models on CodeXGLUE and Big-Vul datasets

### Cloud Infrastructure Scanning
Support for multiple cloud platforms (AWS, Azure, GCP) and Kubernetes
- **Powered by**:
  - Prowler for comprehensive cloud security assessment
  - Cloud Custodian for policy enforcement
  - Multi-cloud security monitoring and compliance

Prowler provides:
- Continuous security monitoring
- Compliance framework checks (CIS, NIST, PCI-DSS, etc.)
- Real-time security assessments
- Incident response capabilities
- Hardening recommendations
- Forensics readiness
- Kubernetes security scanning
- Multi-cloud compliance reporting

### SBOM Vulnerability Detection
Analyze software dependencies for known vulnerabilities
- **Powered by**:
  - Syft for SBOM generation
  - Grype for vulnerability scanning
  - OWASP Dependency-Check

### CIS Benchmark Checks
Automated compliance checking against CIS benchmarks
- **Powered by**:
  - OpenSCAP
  - Inspec for compliance testing

### Modular Plugin Architecture
Extensible design for adding new scanners and analyzers
- **Powered by**:
  - Click framework for CLI interface
  - Pydantic for configuration management

### Comprehensive Reporting
Generate detailed reports in multiple formats (JSON, HTML, PDF)
- **Powered by**:
  - Jinja2 for HTML template rendering
  - WeasyPrint for PDF generation

### Real-time Analysis
Immediate feedback and continuous monitoring capabilities
- **Powered by**:
  - Watchdog for file system monitoring
  - Slack API for notifications

### Customizable AI Models
Train and fine-tune models for specific security needs
- **Powered by**:
  - Hugging Face Transformers
  - PyTorch Lightning
  - Scikit-learn

## Vulnerability Detection

### Code Security Analysis
SecAuditAI performs comprehensive code analysis to detect various security vulnerabilities:

1. **Authentication & Authorization Issues**:
   - Broken Access Control
   - Insecure Direct Object References (IDOR)
   - Missing Authentication
   - Session Management Issues
   - JWT Implementation Flaws

2. **Injection Vulnerabilities**:
   - SQL Injection
   - NoSQL Injection
   - Command Injection
   - LDAP Injection
   - XPath Injection

3. **Cross-Site Scripting (XSS)**:
   - Stored XSS
   - Reflected XSS
   - DOM-based XSS
   - Content Security Policy (CSP) Issues

4. **Data Security Issues**:
   - Sensitive Data Exposure
   - Insecure Deserialization
   - XML External Entities (XXE)
   - Insecure File Uploads

5. **Security Misconfigurations**:
   - Default Credentials
   - Debug Features Enabled
   - Directory Listing
   - Unnecessary Services
   - Insecure Headers

### SBOM Analysis and Vulnerability Matching

SecAuditAI performs comprehensive SBOM analysis with the following capabilities:

1. **Dependency Analysis**:
   - Package Name and Version Detection
   - Direct and Transitive Dependencies
   - License Analysis
   - Dependency Tree Visualization

2. **Vulnerability Database Integration**:
   - National Vulnerability Database (NVD)
   - GitHub Security Advisories
   - OSV Database
   - Snyk Vulnerability Database
   - OSS Index

3. **Vulnerability Matching Process**:
   - CVE ID Matching
   - Version Range Analysis
   - Severity Scoring (CVSS)
   - Exploit Availability Check
   - Patch Availability Verification

4. **Advanced Analysis**:
   - Dependency Confusion Detection
   - Supply Chain Attack Prevention
   - Malicious Package Detection
   - Outdated Dependency Analysis
   - License Compliance Checking

### AI-Powered Analysis

SecAuditAI uses advanced AI models for vulnerability detection:

1. **Static Analysis**:
   - Pattern Recognition
   - Code Flow Analysis
   - Data Flow Analysis
   - Control Flow Analysis
   - Taint Analysis

2. **Semantic Analysis**:
   - Context-Aware Vulnerability Detection
   - False Positive Reduction
   - Custom Rule Learning
   - Code Understanding
   - Security Pattern Recognition

3. **Training Data Sources**:
   - CodeXGLUE Dataset
   - Big-Vul Dataset
   - Devign Dataset
   - SARD Dataset
   - Custom Training Data

## Supported Languages and Frameworks

### Code Analysis
- **Languages**:
  - Python (using ast and tokenize)
  - JavaScript/TypeScript (using Esprima)
  - Java (using JavaParser)
  - C/C++ (using Clang)
  - Go (using go/parser)
  - Ruby (using parser)
  - PHP (using PHP-Parser)
  - Rust (using syn)
  - Swift (using SwiftSyntax)
  - Kotlin (using Kotlin Parser)

- **Frameworks**:
  - Django (using django-inspector)
  - Flask (using flask-inspector)
  - Express.js (using express-validator)
  - Spring Boot (using spring-security)
  - React (using eslint-plugin-react)
  - Vue.js (using vue-eslint-parser)
  - Laravel (using laravel-security)
  - Ruby on Rails (using brakeman)
  - FastAPI (using fastapi-security)

### Container Image Analysis
- **Base Images**:
  - Alpine (using apk-tools)
  - Ubuntu (using dpkg)
  - Debian (using dpkg)
  - CentOS (using rpm)
  - Red Hat Enterprise Linux (using rpm)
  - Amazon Linux (using rpm)

- **Container Runtimes**:
  - Docker (using Docker SDK)
  - containerd (using containerd API)
  - CRI-O (using CRI-O API)

## Open Source Credits

We would like to acknowledge and thank the following open-source security tools and AI frameworks that power SecAuditAI:

### Security Tools
- **CodeBERT**: Microsoft Research's code understanding model
- **Tree-sitter**: Language parsing
- **Syft**: SBOM generation
- **Grype**: Vulnerability scanning
- **OWASP Dependency-Check**: Dependency analysis
- **OpenSCAP**: Security compliance
- **Inspec**: Compliance testing
- **Cloud Custodian**: Cloud security
- **Prowler**: Cloud and Kubernetes security assessment and compliance

### AI/ML Frameworks
- **PyTorch**: Deep learning framework
- **Transformers**: Hugging Face's NLP library
- **Scikit-learn**: Machine learning
- **Lightning**: PyTorch training framework

## Installation

```bash
# Install from PyPI
pip install secauditai

# Install with development dependencies
pip install secauditai[dev]

# Install from source
git clone https://github.com/Parthasarathi7722/secauditai.git
cd secauditai
pip install -e .
```

## Quick Start

```bash
# Show help
secauditai --help

# List available scanners
secauditai scanners list

# Run a basic scan
secauditai scan <target> [options]
```

## Usage Guide

### Cloud Security Scanning

#### AWS Security Assessment
```bash
# Basic AWS scan
secauditai scan aws --profile default --region us-east-1

# AWS scan with CIS compliance
secauditai scan aws --profile default --region us-east-1 --compliance cis

# AWS scan with specific checks
secauditai scan aws --profile default --checks iam,ec2,s3

# AWS scan with custom output
secauditai scan aws --profile default --output-format json --output-file aws_scan.json
```

#### Azure Security Assessment
```bash
# Basic Azure scan
secauditai scan azure --subscription-id <id> --resource-group <group>

# Azure scan with NIST compliance
secauditai scan azure --subscription-id <id> --compliance nist

# Azure scan with specific services
secauditai scan azure --subscription-id <id> --services storage,network,compute
```

#### GCP Security Assessment
```bash
# Basic GCP scan
secauditai scan gcp --project <project-id> --region us-central1

# GCP scan with PCI compliance
secauditai scan gcp --project <project-id> --compliance pci

# GCP scan with specific resources
secauditai scan gcp --project <project-id> --resources compute,storage,iam
```

#### Kubernetes Security Assessment
```bash
# Basic Kubernetes scan
secauditai scan kubernetes --cluster <cluster-name>

# Kubernetes scan with namespace
secauditai scan kubernetes --cluster <cluster-name> --namespace default

# Kubernetes scan with specific checks
secauditai scan kubernetes --cluster <cluster-name> --checks pods,services,ingress
```

### Code Security Scanning

```bash
# Scan Python code
secauditai scan code --path /path/to/project --language python

# Scan JavaScript code
secauditai scan code --path /path/to/project --language javascript

# Scan with specific checks
secauditai scan code --path /path/to/project --checks sql-injection,xss,secrets

# Scan with AI analysis
secauditai scan code --path /path/to/project --enable-ai

# Scan with custom rules
secauditai scan code --path /path/to/project --rules-file custom_rules.yaml
```

### SBOM Analysis

```bash
# Generate SBOM
secauditai scan sbom --path /path/to/project

# Check for vulnerabilities
secauditai scan sbom --path /path/to/project --check-vulnerabilities

# Check license compliance
secauditai scan sbom --path /path/to/project --check-licenses

# Generate dependency tree
secauditai scan sbom --path /path/to/project --generate-tree
```

### Container Security Scanning

```bash
# Scan Docker image
secauditai scan container --image nginx:latest

# Scan with specific checks
secauditai scan container --image nginx:latest --checks vulnerabilities,config,secrets

# Scan with custom policies
secauditai scan container --image nginx:latest --policies-file custom_policies.yaml
```

### Report Generation

SecAuditAI supports generating reports in multiple formats (JSON, HTML, PDF) for different types of scans. Here's how to generate reports for specific scan types:

#### AWS Security Report
```bash
# Generate JSON report
secauditai scan aws --profile default --region us-east-1 --output-format json --output-file aws_report.json

# Generate HTML report with custom template
secauditai scan aws --profile default --region us-east-1 --output-format html --output-file aws_report.html --template custom_aws_template.html

# Generate PDF report
secauditai scan aws --profile default --region us-east-1 --output-format pdf --output-file aws_report.pdf

# Generate compliance report
secauditai scan aws --profile default --region us-east-1 --compliance cis --output-format pdf --output-file aws_cis_report.pdf
```

#### Kubernetes Security Report
```bash
# Generate JSON report
secauditai scan kubernetes --cluster my-cluster --output-format json --output-file k8s_report.json

# Generate HTML report with namespace filter
secauditai scan kubernetes --cluster my-cluster --namespace default --output-format html --output-file k8s_report.html

# Generate PDF report with specific checks
secauditai scan kubernetes --cluster my-cluster --checks pods,services --output-format pdf --output-file k8s_report.pdf
```

#### Code Security Report
```bash
# Generate JSON report for Python code
secauditai scan code --path /path/to/project --language python --output-format json --output-file code_report.json

# Generate HTML report with AI analysis
secauditai scan code --path /path/to/project --language python --enable-ai --output-format html --output-file code_report.html

# Generate PDF report with specific checks
secauditai scan code --path /path/to/project --language python --checks sql-injection,xss --output-format pdf --output-file code_report.pdf
```

#### SBOM Analysis Report
```bash
# Generate JSON report with vulnerability data
secauditai scan sbom --path /path/to/project --check-vulnerabilities --output-format json --output-file sbom_report.json

# Generate HTML report with dependency tree
secauditai scan sbom --path /path/to/project --generate-tree --output-format html --output-file sbom_report.html

# Generate PDF report with license compliance
secauditai scan sbom --path /path/to/project --check-licenses --output-format pdf --output-file sbom_report.pdf
```

#### Container Security Report
```bash
# Generate JSON report
secauditai scan container --image nginx:latest --output-format json --output-file container_report.json

# Generate HTML report with specific checks
secauditai scan container --image nginx:latest --checks vulnerabilities,config --output-format html --output-file container_report.html

# Generate PDF report with custom policies
secauditai scan container --image nginx:latest --policies-file security_policies.yaml --output-format pdf --output-file container_report.pdf
```

#### Report Management
```bash
# List all available reports
secauditai report list

# Show details of a specific report
secauditai report show <report-id>

# Delete a report
secauditai report delete <report-id>

# Export report to different format
secauditai report export <report-id> --format <new-format> --output <new-file>
```

#### Report Templates
SecAuditAI comes with built-in templates for different report types, but you can also use custom templates:

```bash
# List available templates
secauditai report templates list

# Use custom template for HTML report
secauditai scan aws --profile default --output-format html --template /path/to/custom_template.html

# Generate report with specific sections
secauditai scan aws --profile default --output-format html --sections summary,findings,recommendations
```

#### Report Configuration
```bash
# Set default report format
secauditai config set report.default_format html

# Set default output directory
secauditai config set report.output_dir /path/to/reports

# Configure report sections
secauditai config set report.sections summary,findings,recommendations,metadata

# Set report styling
secauditai config set report.style dark
```

#### Report Examples

1. **Comprehensive AWS Security Report**
```bash
secauditai scan aws \
  --profile default \
  --region us-east-1 \
  --compliance cis \
  --output-format html \
  --output-file aws_security_report.html \
  --sections summary,findings,recommendations,compliance \
  --style dark
```

2. **Detailed Code Security Report with AI Analysis**
```bash
secauditai scan code \
  --path /path/to/project \
  --language python \
  --enable-ai \
  --output-format pdf \
  --output-file code_security_report.pdf \
  --sections summary,findings,ai_analysis,recommendations \
  --template custom_code_template.html
```

3. **SBOM Report with Vulnerability Data**
```bash
secauditai scan sbom \
  --path /path/to/project \
  --check-vulnerabilities \
  --check-licenses \
  --generate-tree \
  --output-format json \
  --output-file sbom_analysis.json \
  --include-dependencies \
  --include-vulnerabilities \
  --include-licenses
```

### Configuration

```bash
# Show current configuration
secauditai config show

# Set configuration values
secauditai config set <key> <value>

# Example: Set notification settings
secauditai config set notifications.slack.webhook_url <url>
secauditai config set notifications.email.smtp_server <server>

# Example: Set AI settings
secauditai config set ai.provider ollama
secauditai config set ai.model codebert
```

### Monitoring

```bash
# Start monitoring
secauditai monitor start

# Configure monitoring
secauditai monitor config --interval 300 --notifications slack,email

# Stop monitoring
secauditai monitor stop
```

### Advanced Usage

#### Custom Checks
```bash
# Add custom check
secauditai checks add --name custom_check --path /path/to/check.py

# List available checks
secauditai checks list

# Enable/disable checks
secauditai checks enable custom_check
secauditai checks disable custom_check
```

#### Plugin Management
```bash
# List installed plugins
secauditai plugins list

# Install plugin
secauditai plugins install <plugin-name>

# Remove plugin
secauditai plugins remove <plugin-name>
```

#### Compliance Frameworks
```bash
# List supported frameworks
secauditai compliance list

# Generate compliance report
secauditai compliance generate --framework cis --provider aws

# Check compliance status
secauditai compliance check --framework cis --provider aws
```

### Environment Variables

```bash
# Set API keys
export SECAUDITAI_AWS_ACCESS_KEY_ID=<key>
export SECAUDITAI_AWS_SECRET_ACCESS_KEY=<secret>
export SECAUDITAI_AZURE_CLIENT_ID=<id>
export SECAUDITAI_AZURE_CLIENT_SECRET=<secret>
export SECAUDITAI_GCP_CREDENTIALS=<path>

# Set notification settings
export SECAUDITAI_SLACK_WEBHOOK_URL=<url>
export SECAUDITAI_EMAIL_SMTP_SERVER=<server>
```

### Common Examples

1. **Full AWS Security Assessment with AI Analysis**
```bash
secauditai scan aws \
  --profile default \
  --region us-east-1 \
  --compliance cis \
  --enable-ai \
  --output-format html \
  --output-file aws_security_report.html
```

2. **Code Security Scan with Custom Rules**
```bash
secauditai scan code \
  --path /path/to/project \
  --language python \
  --enable-ai \
  --checks all \
  --rules-file custom_rules.yaml \
  --output-format json
```

3. **Container Security Assessment with Policies**
```bash
secauditai scan container \
  --image nginx:latest \
  --checks vulnerabilities,config,secrets \
  --policies-file security_policies.yaml \
  --output-format pdf
```

4. **Continuous Monitoring Setup**
```bash
# Configure monitoring
secauditai monitor config \
  --interval 300 \
  --notifications slack,email \
  --checks high,medium

# Start monitoring
secauditai monitor start
```

5. **Compliance Report Generation**
```bash
secauditai compliance generate \
  --framework cis \
  --provider aws \
  --format pdf \
  --output aws-cis-report.pdf
```

For more detailed information about specific commands and options, use:
```bash
secauditai <command> --help
```

## Development

### Setting up Development Environment

1. **Clone the repository**:
```bash
git clone https://github.com/Parthasarathi7722/secauditai.git
cd secauditai
```

2. **Create and activate virtual environment**:
```bash
# On Windows
python -m venv venv
.\venv\Scripts\activate

# On Linux/macOS
python -m venv venv
source venv/bin/activate
```

3. **Install development dependencies**:
```bash
pip install -e ".[dev]"
```

4. **Install pre-commit hooks**:
```bash
pre-commit install
```

5. **Run tests**:
```bash
pytest
```

### Development Guidelines

1. **Code Style**:
   - Follow PEP 8 for Python code
   - Use type hints for all function parameters and return values
   - Document all public functions and classes with docstrings
   - Keep functions small and focused on a single responsibility

2. **Testing**:
   - Write unit tests for all new features
   - Maintain test coverage above 90%
   - Use pytest for testing
   - Include integration tests for complex features

3. **Documentation**:
   - Update README.md for new features
   - Add docstrings to all new code
   - Update API documentation
   - Include usage examples

4. **Version Control**:
   - Use meaningful commit messages
   - Create feature branches for new work
   - Submit pull requests for review
   - Keep the main branch stable

### Project Structure
```
secauditai/
├── secauditai/              # Main package
│   ├── core/               # Core functionality
│   ├── plugins/            # Scanner plugins
│   ├── templates/          # Report templates
│   └── utils/              # Utility functions
├── tests/                  # Test suite
├── docs/                   # Documentation
├── examples/               # Usage examples
└── scripts/                # Development scripts
```

## Contributing

We welcome contributions from the community! Here's how you can help:

1. **Report Issues**:
   - Check existing issues before creating new ones
   - Provide detailed information about the problem
   - Include steps to reproduce the issue

2. **Submit Pull Requests**:
   - Fork the repository
   - Create a feature branch
   - Make your changes
   - Submit a pull request with a clear description

3. **Code Review**:
   - Review open pull requests
   - Provide constructive feedback
   - Help maintain code quality

4. **Documentation**:
   - Improve existing documentation
   - Add examples and tutorials
   - Fix typos and errors

## Troubleshooting

### Common Issues

1. **Installation Problems**:
   - Ensure Python 3.8+ is installed
   - Check virtual environment setup
   - Verify all dependencies are installed

2. **Scanner Issues**:
   - Check scanner configuration
   - Verify required permissions
   - Ensure target is accessible

3. **Report Generation**:
   - Check template files
   - Verify output directory permissions
   - Ensure required dependencies are installed

4. **AI Analysis**:
   - Check model availability
   - Verify API keys and credentials
   - Ensure sufficient resources

### Getting Help

- Check the [documentation](https://github.com/Parthasarathi7722/secauditai/docs)
- Search [existing issues](https://github.com/Parthasarathi7722/secauditai/issues)
- Join our [Discord community](https://discord.gg/secauditai)
- Contact the maintainers

## License

SecAuditAI is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.