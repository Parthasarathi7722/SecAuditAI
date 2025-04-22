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
Support for multiple cloud platforms (AWS, Azure, GCP)
- **Powered by**:
  - Cloud Custodian for policy enforcement
  - Scout Suite for cloud security assessment

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
- **Scout Suite**: Cloud security assessment

### AI/ML Frameworks
- **PyTorch**: Deep learning framework
- **Transformers**: Hugging Face's NLP library
- **Scikit-learn**: Machine learning
- **Lightning**: PyTorch training framework

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
- All the maintainers of the open-source projects we depend on
