# SecAuditAI

SecAuditAI is an AI-powered security audit tool that helps identify security vulnerabilities in your code, cloud infrastructure, and dependencies. It combines traditional security scanning with AI-powered analysis to provide comprehensive security insights.

## Features

- **Code Security Scanning**: Analyze source code for security vulnerabilities
- **Cloud Infrastructure Scanning**: Audit AWS, Azure, and GCP resources
- **SBOM Analysis**: Generate and analyze Software Bill of Materials
- **AI-Powered Analysis**: Use machine learning to detect complex security issues
- **Multiple Report Formats**: Generate reports in JSON, HTML, and PDF
- **Interactive TUI**: User-friendly terminal interface
- **Plugin Architecture**: Extensible design for adding new scanners

## Installation

### Prerequisites

- Python 3.8 or higher
- wkhtmltopdf (for PDF report generation)
- Tree-sitter language parsers
- Cloud provider credentials (for cloud scanning)

### Install from PyPI

```bash
pip install secauditai
```

### Install from Source

1. Clone the repository:
```bash
git clone https://github.com/yourusername/secauditai.git
cd secauditai
```

2. Install dependencies:
```bash
pip install -e .
```

3. Install Tree-sitter language parsers:
```bash
secauditai init
```

## Usage

### Command Line Interface

```bash
# Initialize configuration
secauditai init

# Run interactive TUI
secauditai interactive

# Scan AWS infrastructure
secauditai scan aws --profile default --region us-east-1

# Scan Azure infrastructure
secauditai scan azure --subscription <sub-id> --resource-group <rg-name>

# Scan source code
secauditai scan code --path /path/to/code --language python

# Generate and analyze SBOM
secauditai scan sbom --path /path/to/project

# View available reports
secauditai reports list
```

### Configuration

Configuration is stored in `~/.secauditai/config.yaml`. You can edit this file directly or use the interactive TUI to configure settings.

#### Cloud Configuration

```yaml
cloud:
  aws_profile: default
  aws_region: us-east-1
  azure_subscription: <subscription-id>
  azure_resource_group: <resource-group>
  gcp_project: <project-id>
```

#### AI Configuration

```yaml
ai:
  model_name: secauditai-base
  cache_dir: ~/.secauditai/models
  max_tokens: 2048
  temperature: 0.7
```

#### Scanner Configuration

```yaml
scanner:
  code:
    enabled_checks:
      - hardcoded_secrets
      - sql_injection
      - xss
    severity_threshold: medium
  sbom:
    check_vulnerabilities: true
    check_licenses: true
    allowed_licenses:
      - MIT
      - Apache-2.0
      - BSD-3-Clause
```

### Model Training

SecAuditAI uses machine learning models for enhanced security analysis. You can train custom models using your own datasets:

```bash
# Download security datasets
secauditai ai dataset --type vulnerabilities

# Train a custom model
secauditai ai train --model custom-model --dataset /path/to/dataset --epochs 10
```

### Plugin Development

To create a new scanner plugin:

1. Create a new Python file in `secauditai/plugins/scanners/`
2. Implement the `ScannerPlugin` interface
3. Register the plugin in `secauditai/plugins/__init__.py`

Example plugin structure:
```python
from .. import ScannerPlugin

class CustomScanner(ScannerPlugin):
    def __init__(self):
        self.checks = self._load_checks()
    
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        # Implement scanning logic
        pass
    
    def get_name(self) -> str:
        return "custom"
    
    def get_description(self) -> str:
        return "Custom security scanner"
```

## Report Formats

SecAuditAI generates reports in multiple formats:

- **JSON**: Machine-readable format for integration with other tools
- **HTML**: Interactive web-based report with detailed findings
- **PDF**: Printable report for documentation and sharing

Example report structure:
```json
{
  "scan_type": "code",
  "timestamp": "2024-01-01T12:00:00Z",
  "results": {
    "scanner": "code",
    "target": "/path/to/code",
    "findings": [
      {
        "check_id": "code-001",
        "resource": "file.py:42",
        "status": "failed",
        "message": "Hardcoded secret found",
        "severity": "high",
        "recommendation": "Use environment variables"
      }
    ],
    "summary": {
      "total": 1,
      "failed": 1,
      "passed": 0,
      "error": 0
    }
  }
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Tree-sitter](https://tree-sitter.github.io/tree-sitter/) for code parsing
- [Syft](https://github.com/anchore/syft) for SBOM generation
- [Ollama](https://ollama.ai/) for AI model serving
- [Rich](https://github.com/Textualize/rich) for beautiful terminal output
