# Tools Review and Dependencies

This document summarizes the review of all tools and dependencies used in SecAuditAI.

## Tool Status Summary

### ✅ Core Tools (Required)
- **Python 3.8+** - Runtime environment
- **boto3** - AWS SDK for cloud scanning (Python package)
- **All packages in requirements.txt** - Core dependencies

### ✅ Optional CLI Tools (Gracefully Handled)

#### 1. **Syft** (SBOM Generation)
- **Status**: ✅ Installed in Dockerfile
- **Usage**: Used by `SBOMScanner` in `secauditai/plugins/scanners/sbom_scanner.py`
- **Installation**: 
  - Docker: Already installed via install script
  - Local: `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin`
- **Fallback**: Returns empty SBOM if not available (handled gracefully)

#### 2. **Prowler** (Cloud Security Scanning)
- **Status**: ⚠️ Optional, not installed in Dockerfile
- **Usage**: Used by `CloudScanner` in `secauditai/plugins/scanners/cloud_scanner.py`
- **Installation Options**:
  - Python wrapper: `pip install prowler-cloud`
  - CLI tool: Follow instructions at https://github.com/prowler-cloud/prowler
- **Fallback**: Returns empty results if not available (handled gracefully)
- **Note**: There's an unused `ProwlerScanner` class in `secauditai/plugins/cloud/prowler.py` that duplicates functionality

#### 3. **pdfkit** (PDF Report Generation)
- **Status**: ✅ Optional, handled gracefully
- **Usage**: Used by `ReportGenerator` in `secauditai/reports.py`
- **Installation**: 
  - Python package: `pip install pdfkit` (requires `wkhtmltopdf` system package)
  - System package: Install `wkhtmltopdf` separately
- **Fallback**: Falls back to HTML format if not available

### ❌ Removed/Unused Tools

#### 1. **grype**
- **Status**: ❌ Removed from setup.py
- **Reason**: Not used anywhere in the codebase
- **Note**: Grype is a CLI tool (like Syft) and would need separate installation if needed

#### 2. **prowler.py duplicate**
- **Status**: ⚠️ Unused duplicate file
- **Location**: `secauditai/plugins/cloud/prowler.py`
- **Note**: Contains `ProwlerScanner` class that's not imported anywhere. The actual Prowler integration is in `cloud_scanner.py`

## Dependency Categories

### Python Packages (install_requires)
All packages in `setup.py`'s `install_requires` are valid Python packages available on PyPI.

### Optional Extras
- **dev**: Development tools (pytest, black, flake8, etc.)
- **security**: Optional security tools (currently only cloud-custodian)
- **pdf**: PDF generation support (pdfkit)

### CLI Tools (Not in setup.py)
These are installed separately and handled gracefully:
- `syft` - Installed in Dockerfile
- `prowler` - Optional, user-installed
- `wkhtmltopdf` - Required for pdfkit, user-installed

## Recommendations

1. ✅ **DONE**: Removed `syft` and `grype` from `install_requires` (they're CLI tools)
2. ✅ **DONE**: Removed `prowler` from `extras_require["security"]` (it's a CLI tool)
3. ✅ **DONE**: Made `pdfkit` optional in extras
4. ✅ **DONE**: Updated README with installation instructions
5. ✅ **DONE**: Updated Dockerfile with comments about optional tools
6. ⚠️ **TODO**: Consider removing or documenting `secauditai/plugins/cloud/prowler.py` if unused

## Installation Commands

### Full Installation (with all optional tools)
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install optional tools
# Syft (for SBOM)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Prowler (for cloud scanning)
pip install prowler-cloud

# PDF support
pip install pdfkit
# And install wkhtmltopdf system package
```

### Minimal Installation (core only)
```bash
pip install -r requirements.txt
# All scanners will work, but some features will be limited
```

