# SecAuditAI

A powerful CLI security audit tool that combines AI-powered code analysis, cloud infrastructure scanning, SBOM vulnerability detection, and CIS benchmark checks.

## Features

- **AI-Powered Code Analysis**: Detect security vulnerabilities in source code using advanced LLM models
- **Cloud Infrastructure Scanning**: Support for multiple cloud platforms (AWS, Azure, GCP)
- **SBOM Vulnerability Detection**: Analyze software dependencies for known vulnerabilities
- **CIS Benchmark Checks**: Automated compliance checking against CIS benchmarks
- **Modular Plugin Architecture**: Extensible design for adding new scanners and analyzers
- **Comprehensive Reporting**: Generate detailed reports in multiple formats (JSON, HTML, PDF)
- **Real-time Analysis**: Immediate feedback and continuous monitoring capabilities
- **Customizable AI Models**: Train and fine-tune models for specific security needs

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

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- CodeXGLUE dataset
- Big-Vul dataset
- Devign dataset
- SARD dataset
- Ollama for LLM integration
