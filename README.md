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

## AI Framework and Training

### LLM Integration

SecAuditAI uses a combination of pre-trained language models and custom-trained models for security analysis:

1. **Base Models**
   - CodeBERT for code analysis
   - SecurityBERT for vulnerability detection
   - Custom fine-tuned models for specific security domains

2. **Model Architecture**
   - Transformer-based architecture
   - Multi-task learning capabilities
   - Domain-specific embeddings
   - Attention mechanisms for code context

3. **Training Pipeline**
   ```bash
   # Prepare training data
   secauditai train prepare --dataset security_dataset --output training_data

   # Train base model
   secauditai train base --data training_data --model codebert --epochs 10

   # Fine-tune for specific task
   secauditai train finetune --model codebert --task vulnerability_detection --data task_data

   # Evaluate model
   secauditai train evaluate --model trained_model --test_data test_set
   ```

4. **Custom Model Training**
   ```bash
   # Create custom training configuration
   secauditai train config create --name custom_model --type transformer

   # Add training parameters
   secauditai train config set custom_model epochs 20
   secauditai train config set custom_model batch_size 32
   secauditai train config set custom_model learning_rate 0.0001

   # Start training
   secauditai train start --config custom_model --data training_data
   ```

### AI Framework Components

1. **Data Processing**
   - Code parsing and tokenization
   - AST generation
   - Semantic analysis
   - Feature extraction

2. **Model Components**
   - Code understanding
   - Vulnerability detection
   - Pattern recognition
   - Risk assessment

3. **Training Data Requirements**
   - Labeled security vulnerabilities
   - Code samples with known issues
   - Security best practices
   - Compliance requirements

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

## Detailed Usage Guide

### Docker-based Scanning

1. **Basic Setup**
   ```bash
   # Build the Docker image
   docker build -t secauditai .

   # Run a basic code scan
   docker run -v $(pwd):/app secauditai scan code /app/path/to/repo

   # Run with custom configuration
   docker run -v $(pwd):/app -v $(pwd)/config.yaml:/app/config.yaml secauditai scan code /app/path/to/repo --config /app/config.yaml
   ```

2. **Cloud Infrastructure Scanning**
   ```bash
   # AWS scanning with credentials
   docker run -v $(pwd):/app \
     -e AWS_ACCESS_KEY_ID=your_key \
     -e AWS_SECRET_ACCESS_KEY=your_secret \
     -e AWS_DEFAULT_REGION=your_region \
     secauditai scan aws --profile default

   # Azure scanning with credentials
   docker run -v $(pwd):/app \
     -e AZURE_CLIENT_ID=your_client_id \
     -e AZURE_CLIENT_SECRET=your_secret \
     -e AZURE_TENANT_ID=your_tenant_id \
     secauditai scan azure --subscription-id your_subscription
   ```

3. **Container Security Scanning**
   ```bash
   # Scan local container images
   docker run -v /var/run/docker.sock:/var/run/docker.sock \
     secauditai container scan local_image:tag

   # Scan remote container images
   docker run secauditai container scan remote_image:tag
   ```

4. **SBOM Generation and Analysis**
   ```bash
   # Generate SBOM for local project
   docker run -v $(pwd):/app secauditai sbom generate /app/path/to/project

   # Analyze SBOM for vulnerabilities
   docker run -v $(pwd):/app secauditai sbom analyze /app/sbom.json
   ```

### Manual Installation Usage

1. **Environment Setup**
   ```bash
   # Create and activate virtual environment
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate

   # Install dependencies
   pip install -r requirements.txt
   pip install -r requirements-dev.txt

   # Install binary tools
   ./scripts/install_tools.sh
   ```

2. **Code Scanning**
   ```bash
   # Basic code scan
   secauditai scan code /path/to/repo

   # Scan with specific languages
   secauditai scan code /path/to/repo --languages python,javascript

   # Scan with custom rules
   secauditai scan code /path/to/repo --rules custom_rules.yaml
   ```

3. **Cloud Infrastructure Scanning**
   ```bash
   # Configure cloud credentials
   export AWS_ACCESS_KEY_ID=your_key
   export AWS_SECRET_ACCESS_KEY=your_secret
   export AWS_DEFAULT_REGION=your_region

   # Run AWS scan
   secauditai scan aws --profile default

   # Run Azure scan
   secauditai scan azure --subscription-id your_subscription
   ```

4. **Container Security**
   ```bash
   # Scan container image
   secauditai container scan image:tag

   # Scan container runtime
   secauditai container scan runtime
   ```

5. **Compliance Checks**
   ```bash
   # Run CIS benchmark check
   secauditai compliance check aws --framework cis

   # Run PCI-DSS compliance check
   secauditai compliance check azure --framework pci
   ```

6. **Report Generation**
   ```bash
   # Generate HTML report
   secauditai report generate scan_results.json --format html

   # Generate PDF report
   secauditai report generate scan_results.json --format pdf
   ```

### Advanced Usage

1. **Custom Model Training**
   ```bash
   # Prepare training data
   secauditai train prepare --dataset security_dataset

   # Train custom model
   secauditai train start --config custom_config.yaml

   # Evaluate model
   secauditai train evaluate --model trained_model
   ```

2. **Integration with CI/CD**
   ```yaml
   # Example GitHub Actions workflow
   name: Security Scan
   on: [push, pull_request]
   jobs:
     scan:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v2
         - name: Run SecAuditAI
           run: |
             docker run -v $(pwd):/app secauditai scan code /app
   ```

3. **Custom Rule Development**
   ```yaml
   # Example custom rule
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

## Troubleshooting Guide

### Common Issues and Solutions

1. **Docker-related Issues**

   ```bash
   # Issue: Docker container fails to start
   # Solution: Check Docker daemon status
   systemctl status docker  # Linux
   Get-Service docker      # Windows PowerShell

   # Issue: Permission denied when mounting volumes
   # Solution: Add user to docker group
   sudo usermod -aG docker $USER
   ```

2. **Binary Tool Issues**

   ```bash
   # Issue: Grype/Syft not found
   # Solution: Reinstall binary tools
   curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
   curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

   # Issue: Prowler not working
   # Solution: Check AWS credentials and reinstall
   pip uninstall prowler-cloud
   pip install prowler-cloud
   ```

3. **Python Dependency Issues**

   ```bash
   # Issue: Module not found
   # Solution: Reinstall dependencies
   pip install -r requirements.txt --force-reinstall

   # Issue: Version conflicts
   # Solution: Create fresh virtual environment
   python -m venv venv_new
   source venv_new/bin/activate
   pip install -r requirements.txt
   ```

4. **Cloud Provider Authentication Issues**

   ```bash
   # AWS Issues
   # Solution: Verify credentials
   aws sts get-caller-identity

   # Azure Issues
   # Solution: Check service principal
   az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID

   # GCP Issues
   # Solution: Verify service account
   gcloud auth activate-service-account --key-file=$GOOGLE_APPLICATION_CREDENTIALS
   ```

5. **Container Security Scanning Issues**

   ```bash
   # Issue: Cannot access Docker daemon
   # Solution: Check Docker socket permissions
   ls -l /var/run/docker.sock
   sudo chmod 666 /var/run/docker.sock

   # Issue: Image scanning fails
   # Solution: Check image accessibility
   docker pull image:tag
   docker inspect image:tag
   ```

6. **SBOM Generation Issues**

   ```bash
   # Issue: SBOM generation fails
   # Solution: Check project structure
   syft dir:/path/to/project --output json

   # Issue: Vulnerability analysis fails
   # Solution: Update vulnerability database
   grype db update
   ```

7. **Report Generation Issues**

   ```bash
   # Issue: HTML report generation fails
   # Solution: Check template files
   secauditai report validate --template template.html

   # Issue: PDF generation fails
   # Solution: Install required system dependencies
   sudo apt-get install -y libcairo2-dev libpango1.0-dev
   ```

8. **AI Model Training Issues**

   ```bash
   # Issue: Training data preparation fails
   # Solution: Check data format
   secauditai train validate --dataset training_data

   # Issue: Model training fails
   # Solution: Check GPU availability
   nvidia-smi  # For NVIDIA GPUs
   secauditai train check --gpu
   ```

### Debugging Tools

1. **Logging Configuration**

   ```bash
   # Enable debug logging
   export SECAUDITAI_LOG_LEVEL=DEBUG

   # View detailed logs
   secauditai scan code /path/to/repo --debug
   ```

2. **Diagnostic Commands**

   ```bash
   # Check system requirements
   secauditai doctor

   # Verify tool installations
   secauditai verify --tools

   # Test cloud connectivity
   secauditai verify --cloud aws,azure,gcp
   ```

3. **Performance Monitoring**

   ```bash
   # Monitor resource usage
   secauditai monitor --resources

   # Profile scan performance
   secauditai scan code /path/to/repo --profile
   ```

### Getting Help

1. **Documentation**
   - Check the [official documentation](https://secauditai.readthedocs.io/)
   - Review [API reference](https://secauditai.readthedocs.io/api/)
   - Browse [examples](https://github.com/yourusername/SecAuditAI/examples)

2. **Community Support**
   - Join our [Discord community](https://discord.gg/secauditai)
   - Check [GitHub Issues](https://github.com/yourusername/SecAuditAI/issues)
   - Visit [Stack Overflow](https://stackoverflow.com/questions/tagged/secauditai)

3. **Reporting Issues**
   ```bash
   # Generate debug information
   secauditai debug --collect

   # Submit bug report
   secauditai bug --report "Description of issue"
   ```