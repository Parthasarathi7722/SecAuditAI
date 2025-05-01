# SecAuditAI User Guide

## Quick Start

### Installation

```bash
# Install using pip
pip install secauditai

# Or from source
git clone https://github.com/yourusername/SecAuditAI.git
cd SecAuditAI
pip install -e .
```

### Basic Usage

```python
from secauditai import SecAuditAI

# Initialize
scanner = SecAuditAI()

# Scan code repository
results = scanner.scan_code("path/to/repo")

# Scan cloud infrastructure
results = scanner.scan_cloud("aws", profile="default")

# Generate SBOM
sbom = scanner.generate_sbom("path/to/project")

# Analyze security
analysis = scanner.analyze_security(results)
```

## Core Features

### 1. Code Security Scanning

```python
# Basic scan
results = scanner.scan_code(
    path="path/to/repo",
    languages=["python", "javascript"],
    exclude=["tests/", "docs/"]
)

# Advanced scan with custom rules
results = scanner.scan_code(
    path="path/to/repo",
    rules=["custom_rule1", "custom_rule2"],
    severity="high",
    confidence=0.9
)
```

### 2. Cloud Security Scanning

```python
# AWS scan
results = scanner.scan_cloud(
    provider="aws",
    profile="default",
    regions=["us-east-1", "us-west-2"],
    services=["ec2", "s3", "rds"]
)

# Azure scan
results = scanner.scan_cloud(
    provider="azure",
    subscription_id="your-subscription-id",
    resource_groups=["prod", "staging"]
)

# GCP scan
results = scanner.scan_cloud(
    provider="gcp",
    project_id="your-project-id",
    regions=["us-central1", "europe-west1"]
)
```

### 3. SBOM Generation and Analysis

```python
# Generate SBOM
sbom = scanner.generate_sbom(
    path="path/to/project",
    format="spdx",
    include_dev=False
)

# Analyze SBOM
analysis = scanner.analyze_sbom(
    sbom=sbom,
    vulnerability_check=True,
    license_check=True
)
```

### 4. Zero-Day Vulnerability Detection

```python
# Detect zero-day vulnerabilities
results = scanner.detect_zero_day(
    code="path/to/code",
    patterns=["pattern1", "pattern2"],
    confidence=0.9
)

# Monitor for zero-day vulnerabilities
scanner.monitor_zero_day(
    path="path/to/monitor",
    interval=300,  # 5 minutes
    callback=alert_function
)
```

### 5. Container Security

```python
# Scan Docker image
results = scanner.scan_container(
    image="your-image:tag",
    check_vulnerabilities=True,
    check_misconfigurations=True
)

# Scan Kubernetes cluster
results = scanner.scan_kubernetes(
    namespace="your-namespace",
    check_pods=True,
    check_services=True
)
```

### 6. Infrastructure as Code Security

```python
# Scan Terraform
results = scanner.scan_terraform(
    directory="path/to/terraform",
    check_variables=True,
    check_resources=True
)

# Scan CloudFormation
results = scanner.scan_cloudformation(
    template="path/to/template.yaml",
    check_resources=True,
    check_parameters=True
)
```

### 7. API Security Testing

```python
# Test API security
results = scanner.test_api(
    url="https://api.example.com",
    check_auth=True,
    check_input_validation=True
)

# Test OpenAPI specification
results = scanner.test_openapi(
    spec="path/to/openapi.yaml",
    check_security_schemes=True,
    check_parameters=True
)
```

## Advanced Features

### 1. Custom Rules

```python
# Create custom rule
rule = {
    "id": "custom-001",
    "name": "Custom SQL Injection",
    "pattern": "raw\s*\([^)]*\+",
    "description": "Detects raw SQL query construction",
    "severity": "high",
    "confidence": 0.9
}

# Add rule
scanner.add_rule(rule)

# Apply custom rules
results = scanner.scan_code(
    path="path/to/repo",
    rules=["custom-001"]
)
```

### 2. Real-time Monitoring

```python
# Start monitoring
scanner.start_monitoring(
    path="path/to/monitor",
    interval=300,  # 5 minutes
    callback=alert_function
)

# Configure alerts
scanner.configure_alerts(
    slack_webhook="your-webhook-url",
    email="your-email@example.com",
    severity=["high", "critical"]
)
```

### 3. Integration with CI/CD

```yaml
# GitHub Actions example
name: Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Security Scan
        run: |
          pip install secauditai
          secauditai scan --target . --output results.json
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: security-results
          path: results.json
```

## Best Practices

1. **Regular Scanning**
   - Schedule daily scans
   - Monitor critical components
   - Review scan results

2. **Configuration**
   - Use appropriate severity levels
   - Configure notifications
   - Set up custom rules

3. **Integration**
   - Add to CI/CD pipeline
   - Configure webhooks
   - Set up dashboards

4. **Maintenance**
   - Keep dependencies updated
   - Review custom rules
   - Monitor performance

## Troubleshooting

See [Troubleshooting Guide](troubleshooting.md) for common issues and solutions.

## Support

For additional support:
1. Check documentation
2. Join community forum
3. Submit issues on GitHub
4. Contact support team 