# SecAuditAI

A powerful CLI security audit tool that combines AI-powered code analysis, cloud infrastructure scanning, SBOM vulnerability detection, and CIS benchmark checks.

## Features

### AI-Powered Code Analysis
Detect security vulnerabilities in source code using advanced LLM models
- **Powered by**:
  - CodeBERT (Microsoft Research) for semantic code analysis
  - Tree-sitter for language parsing
  - PyTorch for model training and inference
  - Transformers library for LLM integration
  - Custom-trained models on CodeXGLUE and Big-Vul datasets

### Cloud Infrastructure Scanning
Support for multiple cloud platforms (AWS, Azure, GCP)
- **Powered by**:
  - AWS SDK (boto3) for AWS scanning
  - Azure SDK for Azure scanning
  - Google Cloud SDK for GCP scanning
  - Cloud Custodian for policy enforcement
  - Scout Suite for cloud security assessment

### SBOM Vulnerability Detection
Analyze software dependencies for known vulnerabilities
- **Powered by**:
  - Syft for SBOM generation
  - Grype for vulnerability scanning
  - OWASP Dependency-Check
  - Snyk Open Source
  - National Vulnerability Database (NVD) API

### CIS Benchmark Checks
Automated compliance checking against CIS benchmarks
- **Powered by**:
  - CIS-CAT Pro Assessor
  - OpenSCAP
  - Inspec for compliance testing
  - AWS Config Rules
  - Azure Policy

### Modular Plugin Architecture
Extensible design for adding new scanners and analyzers
- **Powered by**:
  - Python's importlib for dynamic plugin loading
  - Click framework for CLI interface
  - Pydantic for configuration management
  - PyYAML for plugin configuration

### Comprehensive Reporting
Generate detailed reports in multiple formats (JSON, HTML, PDF)
- **Powered by**:
  - Jinja2 for HTML template rendering
  - WeasyPrint for PDF generation
  - Pandas for data analysis
  - Plotly for visualization
  - Custom report templates

### Real-time Analysis
Immediate feedback and continuous monitoring capabilities
- **Powered by**:
  - Watchdog for file system monitoring
  - Slack API for notifications
  - SMTP for email alerts
  - Redis for caching
  - Prometheus for metrics collection

### Customizable AI Models
Train and fine-tune models for specific security needs
- **Powered by**:
  - Hugging Face Transformers
  - PyTorch Lightning
  - Scikit-learn
  - TensorFlow
  - Custom training pipelines

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

We would like to acknowledge and thank the following open-source projects that power SecAuditAI:

### Core Dependencies
- **Python**: The foundation of our tool
- **Click**: CLI framework
- **Pydantic**: Data validation
- **PyYAML**: Configuration management
- **Jinja2**: Template engine
- **WeasyPrint**: PDF generation
- **Pandas**: Data analysis
- **Plotly**: Visualization
- **Watchdog**: File monitoring
- **Redis**: Caching
- **Prometheus**: Metrics

### Security Tools
- **CodeBERT**: Microsoft Research's code understanding model
- **Tree-sitter**: Language parsing
- **Syft**: SBOM generation
- **Grype**: Vulnerability scanning
- **OWASP Dependency-Check**: Dependency analysis
- **OpenSCAP**: Security compliance
- **Inspec**: Compliance testing
- **Cloud Custodian**: Cloud security
- **Scout Suite**: Cloud security assessment

### AI/ML Libraries
- **PyTorch**: Deep learning framework
- **Transformers**: Hugging Face's NLP library
- **Scikit-learn**: Machine learning
- **TensorFlow**: Deep learning framework
- **Lightning**: PyTorch training framework

### Cloud SDKs
- **boto3**: AWS SDK
- **Azure SDK**: Microsoft Azure
- **Google Cloud SDK**: GCP
- **AWS Config**: AWS compliance
- **Azure Policy**: Azure compliance

### Language Parsers
- **Esprima**: JavaScript parsing
- **JavaParser**: Java parsing
- **Clang**: C/C++ parsing
- **go/parser**: Go parsing
- **parser**: Ruby parsing
- **PHP-Parser**: PHP parsing
- **syn**: Rust parsing
- **SwiftSyntax**: Swift parsing
- **Kotlin Parser**: Kotlin parsing

### Framework Tools
- **django-inspector**: Django analysis
- **flask-inspector**: Flask analysis
- **express-validator**: Express.js validation
- **spring-security**: Spring Boot security
- **eslint-plugin-react**: React analysis
- **vue-eslint-parser**: Vue.js analysis
- **laravel-security**: Laravel security
- **brakeman**: Rails security
- **fastapi-security**: FastAPI security

### Container Tools
- **Docker SDK**: Docker integration
- **containerd API**: Container runtime
- **CRI-O API**: Container runtime
- **apk-tools**: Alpine package management
- **dpkg**: Debian package management
- **rpm**: RPM package management

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Parthasarathi7722/SecAuditAI.git
cd SecAuditAI
```

2. Create and activate a virtual environment:
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux/macOS
python -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize configuration:
```bash
secauditai init
```

## Usage

### Basic Usage
```bash
secauditai scan <target> [options]
```

### Examples

1. Scan a code repository:
```bash
secauditai scan /path/to/repo --type code
```

2. Scan cloud infrastructure:
```bash
secauditai scan aws --profile default
```

3. Generate SBOM and check vulnerabilities:
```bash
secauditai scan /path/to/project --type sbom
```

4. Run CIS benchmark checks:
```bash
secauditai scan aws --type cis
```

5. Real-time monitoring:
```bash
secauditai monitor /path/to/repo --interval 300
```

### Report Generation
```bash
secauditai report list
secauditai report show <report_id>
```

## AI Model Training

For detailed information on training and fine-tuning LLMs for vulnerability detection, see the [LLM Training Guide](docs/llm_training.md).

Key features:
- Support for multiple datasets (CodeXGLUE, Big-Vul, Devign, SARD)
- Custom dataset conversion tools
- Fine-tuning capabilities
- Performance evaluation metrics

## Configuration

Configuration is stored in `~/.secauditai/config.json`. You can modify settings using:
```bash
secauditai config set <key> <value>
```

### Real-time Configuration
```json
{
  "monitoring": {
    "interval": 300,
    "alert_threshold": "high",
    "notifications": {
      "email": "your-email@example.com",
      "slack_webhook": "your-webhook-url"
    }
  }
}
```

## Development

### Setting up Development Environment
```bash
# Windows
.\setup_dev.bat

# Linux/macOS
./setup_dev.sh
```

### Running Tests
```bash
pytest
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Roadmap

- [ ] Implement email notification system
- [ ] Add support for more cloud providers (Alibaba Cloud, Oracle Cloud)
- [ ] Enhance SBOM analysis with dependency graph visualization
- [ ] Add support for more programming languages in code analysis
- [ ] Implement automated fix suggestions for detected vulnerabilities

- [ ] Develop a web dashboard for monitoring and reporting
- [ ] Add support for container security scanning
- [ ] Implement CI/CD pipeline integration
- [ ] Add support for custom security rules and policies
- [ ] Develop a plugin marketplace for community contributions

- [ ] Implement advanced AI models for zero-day vulnerability detection
- [ ] Add support for compliance frameworks (SOC2, ISO 27001, etc.)
- [ ] Develop a threat intelligence integration system
- [ ] Create a vulnerability prediction system
- [ ] Implement automated remediation workflows

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

We extend our deepest gratitude to all the open-source projects and communities that have made SecAuditAI possible. Your contributions to the security and development communities are invaluable.

Special thanks to:
- Microsoft Research for CodeBERT
- OWASP for their security tools and guidelines
- The Python community for their excellent libraries
- The cloud providers for their SDKs and APIs
- All the maintainers of the open-source projects we depend on
