# SecAuditAI

SecAuditAI is a lightweight, plugin-based toolkit for exercising the security-scanning and reporting workflows used in the test suite. It ships with simple scanners for code, cloud configuration, and software bills of materials (SBOMs), along with helpers for reporting and alerting.

## Core capabilities
- **Code scanner**: Greedy regex-based checks for secrets, SQL injection, XSS, access control, CSRF, and file inclusion across Python, JavaScript, Java, and Go files.
- **Cloud scanner**: Wrapper around [Prowler](https://github.com/prowler-cloud/prowler). When Prowler is unavailable, the scanner returns empty results instead of failing the process.
- **SBOM scanner**: Invokes [Syft](https://github.com/anchore/syft) to build an SBOM and enriches it with vulnerability, version, and license checks. Missing Syft results in an empty SBOM so tests can continue.
- **Reporting**: Exports scan results as JSON, HTML, PDF (with a placeholder fallback when `pdfkit` is missing), or CSV. Reports are stored under `~/.secauditai/results` by default.
- **Monitoring & notifications**: Provides in-memory monitoring helpers plus Slack and webhook notifiers used by the test suite.

## Installation
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional external tools used by some scanners:
- `prowler` for cloud assessments
- `syft` for SBOM generation
- `wkhtmltopdf` + `pdfkit` for PDF exports

The scanners will fall back to empty output when these binaries are not present.

## Usage
Run the Click-based CLI directly with Python:
```bash
python -m secauditai.cli scan code --path /path/to/project
python -m secauditai.cli scan aws --region us-east-1
python -m secauditai.cli scan sbom --path /path/to/app
```
Reports are written to `~/.secauditai/results` unless you provide an explicit output path to `ReportGenerator`.

## Testing
```bash
pytest
```
