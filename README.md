# SecAuditAI

SecAuditAI is a security audit tool that scans code, cloud infrastructure, and dependencies for security vulnerabilities. It provides detailed evidence for each finding, making it easier to understand and remediate security issues.

## Core Features

### Code Security Scanner
- Detects hardcoded secrets, SQL injection, XSS, broken access control, CSRF, and file inclusion vulnerabilities
- Supports Python, JavaScript, Java, and Go
- Provides evidence including line numbers, code context, and matched patterns

### Cloud Security Scanner
- AWS infrastructure security scanning
- Checks S3 bucket public access, EC2 security groups, and other misconfigurations
- Includes detailed evidence with resource configurations and access policies

### SBOM Scanner
- Generates Software Bill of Materials using Syft
- Checks for known vulnerabilities, outdated dependencies, and license compliance
- Provides evidence with package versions, CVE details, and license information

### Reporting
- Exports scan results as JSON, HTML, PDF, or CSV
- Reports include detailed evidence for each finding
- Reports stored in `~/.secauditai/results` by default

## Installation
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Optional Tools

These CLI tools enhance functionality but are not required. The scanners will gracefully handle their absence:

#### SBOM Generation
- **Syft** - For SBOM generation (installed in Docker image)
  ```bash
  # Install Syft CLI
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
  ```
  The SBOM scanner will skip if Syft is not available.

#### Cloud Security Scanning
- **Prowler** - For comprehensive cloud security assessments (AWS, Azure, GCP, Kubernetes)
  ```bash
  # Install Prowler CLI (recommended)
  pip install prowler-cloud
  
  # Or install via Docker
  docker pull toniblyx/prowler:latest
  ```
  The cloud scanner will return empty results if Prowler is not available.

#### PDF Report Generation
- **wkhtmltopdf** - For PDF report generation
  ```bash
  # macOS
  brew install wkhtmltopdf
  
  # Ubuntu/Debian
  sudo apt-get install wkhtmltopdf
  
  # Or install pdfkit Python package (requires wkhtmltopdf)
  pip install pdfkit
  ```
  Reports will fall back to HTML format if PDF generation is not available.

## Usage

### Code Scanning
```bash
python -m secauditai.cli scan code --path /path/to/project
python -m secauditai.cli scan code --path /path/to/project --language python
```

### AWS Infrastructure Scanning
```bash
python -m secauditai.cli scan aws --region us-east-1
python -m secauditai.cli scan aws --profile my-profile --region us-east-1
```

### SBOM Generation and Analysis
```bash
python -m secauditai.cli scan sbom --path /path/to/app
```

### Report Formats
All scans generate reports in the specified format (default: JSON):
```bash
python -m secauditai.cli scan code --path /path/to/project --output-format html
python -m secauditai.cli scan code --path /path/to/project --output-format pdf
```

## Evidence in Findings

All findings include detailed evidence:
- **Code findings**: Line numbers, code context, matched patterns, and surrounding code
- **Cloud findings**: Resource configurations, access policies, and security group rules
- **SBOM findings**: Package versions, CVE details, license information, and vulnerability scores

## Testing
```bash
pytest
```
