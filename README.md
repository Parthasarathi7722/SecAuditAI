# SecAuditAI
# This project is on hold for now due to job hunt, however feel free to fork and customise if you wish 
SecAuditAI is a comprehensive security auditing tool that leverages AI to perform automated security assessments across various domains including cloud infrastructure, code analysis, and compliance checks. **Note: This is an experimental tool, and some features, particularly zero-day vulnerability detection, are under active development and should be used with caution in production environments.**

## Features

- **AI-Powered Code Analysis**: Advanced static code analysis using Tree-sitter and custom vulnerability detection models
- **Cloud Infrastructure Scanning**: Comprehensive security assessment for AWS, Azure, and GCP environments
- **SBOM Vulnerability Detection**: Automated Software Bill of Materials analysis and vulnerability scanning
- **CIS Benchmark Checks**: Automated Center for Internet Security benchmark compliance verification
- **Modular Plugin Architecture**: Extensible design allowing easy addition of new scanners and analyzers
- **Comprehensive Reporting**: Detailed security reports with actionable insights and remediation steps
- **Real-time Analysis**: Continuous monitoring and alerting capabilities
- **Compliance Framework Support**: Built-in support for major compliance frameworks (CIS, PCI, HIPAA, NIST, ISO27001)
- **Zero-Day Vulnerability Detection** (Experimental): Advanced AI models for detecting unknown vulnerabilities. **Warning: This feature is experimental and may produce false positives. Use with caution in production environments.**
- **Container Security**: Comprehensive container image scanning and runtime security monitoring
- **Infrastructure as Code Security**: Automated security checks for Terraform, CloudFormation, and ARM templates
- **API Security Testing**: Automated API security testing and vulnerability detection
- **Custom Rule Engine**: Support for custom security rules and policies
- **Integration Support**: Slack notifications and webhook integrations for alerts

## Experimental Features

The following features are marked as experimental and should be used with caution:

1. **Zero-Day Vulnerability Detection**
   - Status: Beta
   - Known Limitations:
     - May produce false positives
     - Requires significant computational resources
     - Limited to specific programming languages
   - Usage Guidelines:
     ```bash
     # Enable experimental features
     export SECAUDITAI_EXPERIMENTAL=true
     
     # Run with caution
     secauditai scan --experimental --zero-day
     ```

2. **Advanced AI Model Training**
   - Status: Alpha
   - Known Limitations:
     - Training data requirements
     - Model accuracy variations
     - Resource intensive
   - Usage Guidelines:
     ```bash
     # Enable model training
     secauditai train --experimental --model custom
     ```

3. **Real-time Security Monitoring**
   - Status: Beta
   - Known Limitations:
     - High resource usage
     - Network overhead
     - Alert fatigue potential
   - Usage Guidelines:
     ```bash
     # Enable real-time monitoring
     secauditai monitor --experimental --real-time
     ```

### Experimental Feature Support

For experimental features, we provide:
- Limited support through GitHub issues
- Community-driven development
- Regular updates and improvements
- Feedback collection mechanism

To report issues with experimental features:
```bash
secauditai feedback --experimental --feature zero-day --issue "description"
```

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

## Underlying Tools and Dependencies

SecAuditAI leverages several powerful open-source tools for its security analysis capabilities. Here's a list of the core tools and how to install them manually if needed:

### Core Tools

1. **Tree-sitter** - For advanced code parsing and analysis
   - Official Page: [https://tree-sitter.github.io/tree-sitter/](https://tree-sitter.github.io/tree-sitter/)
   - Manual Installation:
   ```bash
   # Install build dependencies
   sudo apt-get update
   sudo apt-get install build-essential nodejs npm

   # Install tree-sitter
   npm install -g tree-sitter-cli
   ```

2. **Trivy** - For container and vulnerability scanning
   - Official Page: [https://github.com/aquasecurity/trivy](https://github.com/aquasecurity/trivy)
   - Manual Installation:
   ```bash
   # Download and install
   curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
   ```

3. **Terraform** - For Infrastructure as Code analysis
   - Official Page: [https://www.terraform.io/](https://www.terraform.io/)
   - Manual Installation:
   ```bash
   # Download and install
   wget https://releases.hashicorp.com/terraform/1.5.0/terraform_1.5.0_linux_amd64.zip
   unzip terraform_1.5.0_linux_amd64.zip
   sudo mv terraform /usr/local/bin/
   ```

4. **AWS CLI** - For AWS infrastructure scanning
   - Official Page: [https://aws.amazon.com/cli/](https://aws.amazon.com/cli/)
   - Manual Installation:
   ```bash
   curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
   unzip awscliv2.zip
   sudo ./aws/install
   ```

5. **Azure CLI** - For Azure infrastructure scanning
   - Official Page: [https://docs.microsoft.com/en-us/cli/azure/](https://docs.microsoft.com/en-us/cli/azure/)
   - Manual Installation:
   ```bash
   curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
   ```

6. **gcloud CLI** - For GCP infrastructure scanning
   - Official Page: [https://cloud.google.com/sdk/docs/install](https://cloud.google.com/sdk/docs/install)
   - Manual Installation:
   ```bash
   # Add the Cloud SDK distribution URI as a package source
   echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list

   # Import the Google Cloud public key
   curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -

   # Update and install the Cloud SDK
   sudo apt-get update && sudo apt-get install google-cloud-sdk
   ```

### Troubleshooting Tool Installation

If you encounter issues during the automatic installation of these tools, you can:

1. Install them manually using the commands above
2. Set the following environment variables to point to your manual installations:
   ```bash
   export SECAUDITAI_TREE_SITTER_PATH=/path/to/tree-sitter
   export SECAUDITAI_TRIVY_PATH=/path/to/trivy
   export SECAUDITAI_TERRAFORM_PATH=/path/to/terraform
   export SECAUDITAI_AWS_CLI_PATH=/path/to/aws
   export SECAUDITAI_AZURE_CLI_PATH=/path/to/az
   export SECAUDITAI_GCLOUD_PATH=/path/to/gcloud
   ```

3. Verify the installations:
   ```bash
   # Check tool versions
   tree-sitter --version
   trivy --version
   terraform --version
   aws --version
   az --version
   gcloud --version
   ```

### Common Issues and Solutions

1. **Tree-sitter Installation Issues**
   - Problem: Missing Node.js or npm
   - Solution: Install Node.js and npm first:
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
   sudo apt-get install -y nodejs
   ```

2. **Trivy Permission Issues**
   - Problem: Cannot access Docker socket
   - Solution: Add user to docker group:
   ```bash
   sudo usermod -aG docker $USER
   ```

3. **Cloud CLI Authentication Issues**
   - Problem: Credentials not found
   - Solution: Configure credentials manually:
   ```bash
   # AWS
   aws configure
   
   # Azure
   az login
   
   # GCP
   gcloud auth login
   ```

4. **Terraform State Issues**
   - Problem: State file not found
   - Solution: Initialize Terraform:
   ```bash
   terraform init
   ```

For more detailed troubleshooting, refer to the [Troubleshooting Guide](docs/troubleshooting.md).

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

## Security Audit Tools

SecAuditAI integrates with several industry-standard security audit tools. Here's how to install and configure them manually if needed:

### Static Analysis Tools

1. **Bandit** - Python Security Linter
   - Official Page: [https://bandit.readthedocs.io/](https://bandit.readthedocs.io/)
   - Manual Installation:
   ```bash
   pip install bandit
   # Run manually
   bandit -r /path/to/code
   ```

2. **Semgrep** - Fast Static Analysis
   - Official Page: [https://semgrep.dev/](https://semgrep.dev/)
   - Manual Installation:
   ```bash
   python -m pip install semgrep
   # Run manually
   semgrep scan --config auto /path/to/code
   ```

3. **SonarQube** - Code Quality and Security
   - Official Page: [https://www.sonarqube.org/](https://www.sonarqube.org/)
   - Manual Installation:
   ```bash
   # Download and extract
   wget https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-9.9.0.65466.zip
   unzip sonarqube-9.9.0.65466.zip
   cd sonarqube-9.9.0.65466/bin/linux-x86-64
   ./sonar.sh start
   ```

### Container Security Tools

1. **Clair** - Container Vulnerability Analysis
   - Official Page: [https://github.com/quay/clair](https://github.com/quay/clair)
   - Manual Installation:
   ```bash
   # Using Docker
   docker run -d -e POSTGRES_PASSWORD=password -p 5432:5432 postgres:latest
   docker run -d -p 6060:6060 --link postgres:postgres quay.io/coreos/clair:latest
   ```

2. **Anchore** - Container Image Analysis
   - Official Page: [https://anchore.com/](https://anchore.com/)
   - Manual Installation:
   ```bash
   # Using Docker
   docker run -d --name anchore-engine -p 8228:8228 -p 8338:8338 anchore/anchore-engine:latest
   ```

### Cloud Security Tools

1. **Prowler** - AWS Security Assessment
   - Official Page: [https://github.com/prowler-cloud/prowler](https://github.com/prowler-cloud/prowler)
   - Manual Installation:
   ```bash
   pip install prowler
   # Run manually
   prowler aws
   ```