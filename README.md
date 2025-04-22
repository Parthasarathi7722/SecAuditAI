# SecAuditAI

A comprehensive security audit tool that combines AI-powered analysis with traditional security scanning capabilities.

## Features

- AI-powered code analysis
- Cloud infrastructure scanning (AWS, Azure, GCP)
- SBOM vulnerability detection
- CIS benchmark checks
- Multiple report formats (JSON, HTML, PDF)
- Plugin-based architecture
- Interactive TUI

## Installation

### Prerequisites

- Python 3.8 or higher
- Git
- pip (Python package manager)

### Development Environment Setup

#### Linux/macOS

1. Clone the repository:
```bash
git clone https://github.com/Parthasarathi7722/SecAuditAI.git
cd SecAuditAI
```

2. Run the setup script:
```bash
chmod +x setup_dev.sh
./setup_dev.sh
```

#### Windows

1. Clone the repository:
```bash
git clone https://github.com/Parthasarathi7722/SecAuditAI.git
cd SecAuditAI
```

2. Run the setup script:
```bash
setup_dev.bat
```

### Manual Setup

If you prefer to set up the environment manually:

1. Create and activate a virtual environment:
```bash
# Linux/macOS
python -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
pip install -e .
```

3. Initialize the configuration:
```bash
secauditai init
```

## Usage

### Command Line Interface

```bash
# Scan code
secauditai scan code /path/to/code

# Scan cloud infrastructure
secauditai scan cloud aws
secauditai scan cloud azure

# Generate SBOM
secauditai scan sbom /path/to/project

# View reports
secauditai reports list
secauditai reports show <report_id>
```

### Interactive TUI

```bash
secauditai tui
```

## Configuration

Configuration files are stored in `~/.secauditai/` (Linux/macOS) or `%USERPROFILE%\.secauditai\` (Windows).

### Environment Variables

- `SECAUDITAI_API_KEY`: API key for cloud provider access
- `SECAUDITAI_CONFIG_PATH`: Custom configuration path
- `SECAUDITAI_LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)

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
- [Rich](https://github.com/Textualize/rich) for terminal formatting
