# SecAuditAI

SecAuditAI is a comprehensive security auditing tool that leverages AI to perform automated security assessments across various domains including cloud infrastructure, code analysis, and vulnerability detection.

**Note:** This is an experimental tool, and some features, particularly zero-day vulnerability detection, are under active development and should be used with caution in production environments.

## Table of Contents

- [Features](#features)
- [Experimental Features](#experimental-features)
- [Installation](#installation)
- [Usage](#usage)
- [Underlying Tools](#underlying-tools)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)
- [Roadmap](#roadmap)
- [Support](#support)

## Features

- **AI-Powered Code Analysis**: Advanced static code analysis using Tree-sitter and custom vulnerability detection models
- **Cloud Security Scanning**: Comprehensive security assessment for AWS, Azure, and GCP environments using Prowler and native cloud security tools
- **SBOM Vulnerability Detection**: Automated Software Bill of Materials analysis and vulnerability scanning
- **Modular Plugin Architecture**: Extensible design allowing easy addition of new scanners and analyzers
- **Comprehensive Reporting**: Detailed security reports with actionable insights and remediation steps
- **Real-time Analysis**: Continuous monitoring and alerting capabilities
- **Zero-Day Vulnerability Detection** (Experimental): Advanced AI models for detecting unknown vulnerabilities
- **Container Security**: Comprehensive container image scanning and runtime security monitoring
- **Infrastructure as Code Security**: Automated security checks for Terraform, CloudFormation, and ARM templates
- **API Security Testing**: Automated API security testing and vulnerability detection
- **Custom Rule Engine**: Support for custom security rules and policies
- **Integration Support**: Slack notifications and webhook integrations for alerts

## Experimental Features

The following features are marked as experimental and should be used with caution:

### 1. Zero-Day Vulnerability Detection
- **Status**: Beta
- **Known Limitations**:
  - May produce false positives
  - Requires significant computational resources
  - Limited to specific programming languages
- **Usage Guidelines**:
  ```bash
  # Enable experimental features
  export SECAUDITAI_EXPERIMENTAL=true
  
  # Run with caution
  secauditai scan --experimental --zero-day
  ```

### 2. Advanced AI Model Training
- **Status**: Alpha
- **Known Limitations**:
  - Training data requirements
  - Model accuracy variations
  - Resource intensive
- **Usage Guidelines**:
  ```bash
  # Enable model training
  secauditai train --experimental --model custom
  ```

### 3. Real-time Security Monitoring
- **Status**: Beta
- **Known Limitations**:
  - High resource usage
  - Network overhead
  - Alert fatigue potential
- **Usage Guidelines**:
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

## Usage

### Basic Usage

```bash
# Run a security scan
secauditai scan --target /path/to/project

# Generate SBOM
secauditai sbom --format spdx --output sbom.spdx

# Monitor in real-time
secauditai monitor --target aws --region us-east-1
```

### Cloud Security Scanning

#### AWS Security Scanning (Using Prowler)
```bash
# Basic AWS security scan
secauditai scan aws --profile default

# Scan specific AWS services
secauditai scan aws --services ec2,s3,iam

# Run specific security checks
secauditai scan aws --checks check11,check12,check13

# Generate detailed security report
secauditai scan aws --report html --output aws_security_report.html

# Scan with custom rules
secauditai scan aws --rules custom_rules.yaml

# Scan specific regions
secauditai scan aws --regions us-east-1,us-west-2

# Scan with specific severity levels
secauditai scan aws --severity critical,high
```

#### Azure Security Scanning
```bash
# Basic Azure security scan
secauditai scan azure --subscription-id <id>

# Scan specific resource groups
secauditai scan azure --resource-groups rg1,rg2

# Scan with custom rules
secauditai scan azure --rules custom_rules.yaml

# Generate detailed security report
secauditai scan azure --report html --output azure_security_report.html
```

#### GCP Security Scanning
```bash
# Basic GCP security scan
secauditai scan gcp --project-id <id>

# Scan specific services
secauditai scan gcp --services compute,storage,iam

# Scan with custom rules
secauditai scan gcp --rules custom_rules.yaml

# Generate detailed security report
secauditai scan gcp --report html --output gcp_security_report.html
```

### Advanced Usage

```bash
# Enable experimental features
export SECAUDITAI_EXPERIMENTAL=true

# Run with custom rules
secauditai scan --rules custom_rules.yaml

# Generate detailed report
secauditai report --format html --output security_report.html

# Continuous monitoring with notifications
secauditai monitor --notify slack --webhook-url $SLACK_WEBHOOK
```

## Underlying Tools

SecAuditAI leverages several powerful open-source tools for its security analysis capabilities:

### Core Tools

1. **Prowler** - For AWS security assessment
   - Official Page: [https://github.com/prowler-cloud/prowler](https://github.com/prowler-cloud/prowler)
   - Manual Installation:
   ```bash
   # Install using pip
   pip install prowler-cloud

   # Verify installation
   prowler -v
   ```

2. **Tree-sitter** - For advanced code parsing and analysis
   - Official Page: [https://tree-sitter.github.io/tree-sitter/](https://tree-sitter.github.io/tree-sitter/)
   - Manual Installation:
   ```bash
   # Install build dependencies
   sudo apt-get update
   sudo apt-get install build-essential nodejs npm

   # Install tree-sitter
   npm install -g tree-sitter-cli
   ```

3. **Trivy** - For container and vulnerability scanning
   - Official Page: [https://github.com/aquasecurity/trivy](https://github.com/aquasecurity/trivy)
   - Manual Installation:
   ```bash
   # Download and install
   curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
   ```

4. **Terraform** - For Infrastructure as Code analysis
   - Official Page: [https://www.terraform.io/](https://www.terraform.io/)
   - Manual Installation:
   ```bash
   # Download and install
   wget https://releases.hashicorp.com/terraform/1.5.0/terraform_1.5.0_linux_amd64.zip
   unzip terraform_1.5.0_linux_amd64.zip
   sudo mv terraform /usr/local/bin/
   ```

5. **AWS CLI** - For AWS infrastructure scanning
   - Official Page: [https://aws.amazon.com/cli/](https://aws.amazon.com/cli/)
   - Manual Installation:
   ```bash
   curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
   unzip awscliv2.zip
   sudo ./aws/install
   ```

6. **Azure CLI** - For Azure infrastructure scanning
   - Official Page: [https://docs.microsoft.com/en-us/cli/azure/](https://docs.microsoft.com/en-us/cli/azure/)
   - Manual Installation:
   ```bash
   curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
   ```

7. **gcloud CLI** - For GCP infrastructure scanning
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
   export SECAUDITAI_PROWLER_PATH=/path/to/prowler
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
   prowler -v
   tree-sitter --version
   trivy --version
   terraform --version
   aws --version
   az --version
   gcloud --version
   ```

## Documentation

For detailed documentation, please visit our [documentation site](https://parthasarathi7722.github.io/SecAuditAI/).

- [API Reference](https://parthasarathi7722.github.io/SecAuditAI/api/)
- [User Guide](https://parthasarathi7722.github.io/SecAuditAI/guide/)
- [Examples](https://parthasarathi7722.github.io/SecAuditAI/examples/)
- [FAQ](https://parthasarathi7722.github.io/SecAuditAI/faq/)

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Roadmap

### Short-term Goals
- [ ] Improve zero-day detection accuracy
- [ ] Add support for more programming languages
- [ ] Enhance real-time monitoring capabilities
- [ ] Optimize resource usage

### Medium-term Goals
- [ ] Implement machine learning model training pipeline
- [ ] Add support for additional cloud providers
- [ ] Develop plugin marketplace
- [ ] Improve documentation and tutorials

### Long-term Goals
- [ ] Develop advanced threat intelligence integration
- [ ] Create community-driven rule repository
- [ ] Implement automated remediation suggestions
- [ ] Build comprehensive security dashboard

## Support

For support, please:

1. Check our [documentation](https://parthasarathi7722.github.io/SecAuditAI/)
2. Search [existing issues](https://github.com/Parthasarathi7722/SecAuditAI/issues)
3. Create a [new issue](https://github.com/Parthasarathi7722/SecAuditAI/issues/new)

For commercial support, please contact us at support@secauditai.com