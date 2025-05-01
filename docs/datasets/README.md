# Security Audit AI Training Datasets

This directory contains datasets used for training the AI models in SecAuditAI.

## Dataset Structure

```
datasets/
├── api/
│   ├── vulnerabilities.json
│   ├── patterns.json
│   └── examples.json
├── cloud/
│   ├── aws/
│   │   ├── misconfigurations.json
│   │   ├── vulnerabilities.json
│   │   └── best_practices.json
│   ├── azure/
│   │   ├── misconfigurations.json
│   │   ├── vulnerabilities.json
│   │   └── best_practices.json
│   └── gcp/
│       ├── misconfigurations.json
│       ├── vulnerabilities.json
│       └── best_practices.json
├── container/
│   ├── vulnerabilities.json
│   ├── misconfigurations.json
│   └── runtime.json
├── iac/
│   ├── terraform/
│   │   ├── vulnerabilities.json
│   │   └── best_practices.json
│   ├── cloudformation/
│   │   ├── vulnerabilities.json
│   │   └── best_practices.json
│   └── arm/
│       ├── vulnerabilities.json
│       └── best_practices.json
└── zero_day/
    ├── patterns.json
    ├── behaviors.json
    └── indicators.json
```

## Dataset Descriptions

### API Security Dataset

- **vulnerabilities.json**: Known API security vulnerabilities and their patterns
- **patterns.json**: Common attack patterns and their signatures
- **examples.json**: Real-world examples of API security issues

### Cloud Security Datasets

#### AWS
- **misconfigurations.json**: Common AWS misconfigurations
- **vulnerabilities.json**: Known AWS vulnerabilities
- **best_practices.json**: AWS security best practices

#### Azure
- **misconfigurations.json**: Common Azure misconfigurations
- **vulnerabilities.json**: Known Azure vulnerabilities
- **best_practices.json**: Azure security best practices

#### GCP
- **misconfigurations.json**: Common GCP misconfigurations
- **vulnerabilities.json**: Known GCP vulnerabilities
- **best_practices.json**: GCP security best practices

### Container Security Dataset

- **vulnerabilities.json**: Known container vulnerabilities
- **misconfigurations.json**: Common container misconfigurations
- **runtime.json**: Container runtime security issues

### Infrastructure as Code Datasets

#### Terraform
- **vulnerabilities.json**: Known Terraform security issues
- **best_practices.json**: Terraform security best practices

#### CloudFormation
- **vulnerabilities.json**: Known CloudFormation security issues
- **best_practices.json**: CloudFormation security best practices

#### ARM
- **vulnerabilities.json**: Known ARM template security issues
- **best_practices.json**: ARM template security best practices

### Zero-Day Detection Dataset

- **patterns.json**: Common zero-day vulnerability patterns
- **behaviors.json**: Suspicious behaviors and indicators
- **indicators.json**: Indicators of compromise (IOCs)

## Dataset Formats

### Vulnerability Format
```json
{
  "id": "unique_identifier",
  "name": "vulnerability_name",
  "description": "detailed_description",
  "severity": "high|medium|low",
  "category": "category_name",
  "platforms": ["platform1", "platform2"],
  "detection": {
    "patterns": ["pattern1", "pattern2"],
    "indicators": ["indicator1", "indicator2"],
    "signatures": ["signature1", "signature2"]
  },
  "remediation": {
    "steps": ["step1", "step2"],
    "references": ["reference1", "reference2"]
  },
  "examples": [
    {
      "description": "example_description",
      "code": "example_code",
      "explanation": "explanation"
    }
  ]
}
```

### Pattern Format
```json
{
  "id": "unique_identifier",
  "name": "pattern_name",
  "description": "pattern_description",
  "type": "pattern_type",
  "signatures": ["signature1", "signature2"],
  "indicators": ["indicator1", "indicator2"],
  "examples": [
    {
      "description": "example_description",
      "code": "example_code",
      "explanation": "explanation"
    }
  ]
}
```

### Best Practice Format
```json
{
  "id": "unique_identifier",
  "name": "best_practice_name",
  "description": "best_practice_description",
  "category": "category_name",
  "platforms": ["platform1", "platform2"],
  "implementation": {
    "steps": ["step1", "step2"],
    "code_examples": ["example1", "example2"],
    "references": ["reference1", "reference2"]
  },
  "verification": {
    "steps": ["step1", "step2"],
    "tools": ["tool1", "tool2"]
  }
}
```

## Dataset Maintenance

1. **Updates**: Datasets are updated monthly with new vulnerabilities and patterns
2. **Validation**: All entries are validated against known sources
3. **Versioning**: Each dataset has a version number and changelog
4. **Contributions**: External contributions are welcome through pull requests

## Usage Guidelines

1. **Training**: Use datasets for training AI models
2. **Validation**: Validate findings against known patterns
3. **Updates**: Keep datasets up to date
4. **Customization**: Extend datasets for specific needs

## License

All datasets are licensed under the MIT License. See LICENSE file for details.

# Dataset Guide

This guide explains how to use and create datasets for SecAuditAI.

## Available Datasets

### 1. Vulnerability Datasets

```python
from secauditai.datasets import VulnerabilityDataset

# Load vulnerability dataset
dataset = VulnerabilityDataset.load("cve_dataset")

# Get vulnerabilities
vulnerabilities = dataset.get_vulnerabilities(
    severity="high",
    language="python"
)
```

### 2. Security Configuration Datasets

```python
from secauditai.datasets import SecurityConfigDataset

# Load security configuration dataset
dataset = SecurityConfigDataset.load("security_configs")

# Get configurations
configs = dataset.get_configurations(
    provider="aws",
    service="s3"
)
```

### 3. Code Pattern Datasets

```python
from secauditai.datasets import CodePatternDataset

# Load code pattern dataset
dataset = CodePatternDataset.load("code_patterns")

# Get patterns
patterns = dataset.get_patterns(
    language="python",
    category="injection"
)
```

## Dataset Structure

### 1. Vulnerability Dataset

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2023-1234",
      "name": "SQL Injection",
      "description": "SQL injection vulnerability in login form",
      "severity": "high",
      "language": "python",
      "pattern": "raw\s*\([^)]*\+",
      "fix": "Use parameterized queries",
      "references": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234"
      ]
    }
  ]
}
```

### 2. Security Configuration Dataset

```json
{
  "configurations": [
    {
      "provider": "aws",
      "service": "s3",
      "resource": "bucket",
      "setting": "public_access",
      "value": false,
      "recommended": true,
      "description": "S3 bucket should not have public access"
    }
  ]
}
```

### 3. Code Pattern Dataset

```json
{
  "patterns": [
    {
      "language": "python",
      "category": "injection",
      "name": "SQL Injection",
      "pattern": "raw\s*\([^)]*\+",
      "description": "Detects raw SQL query construction",
      "severity": "high",
      "confidence": 0.9
    }
  ]
}
```

## Creating Custom Datasets

### 1. Dataset Builder

```python
from secauditai.datasets import DatasetBuilder

# Initialize builder
builder = DatasetBuilder()

# Add vulnerability
builder.add_vulnerability(
    id="CVE-2023-1234",
    name="SQL Injection",
    description="SQL injection vulnerability",
    severity="high",
    language="python"
)

# Save dataset
builder.save("custom_dataset.json")
```

### 2. Dataset Validator

```python
from secauditai.datasets import DatasetValidator

# Initialize validator
validator = DatasetValidator()

# Validate dataset
is_valid = validator.validate(
    dataset="custom_dataset.json",
    schema="vulnerability_schema.json"
)

# Get validation errors
errors = validator.get_errors()
```

### 3. Dataset Merger

```python
from secauditai.datasets import DatasetMerger

# Initialize merger
merger = DatasetMerger()

# Merge datasets
merged = merger.merge(
    datasets=["dataset1.json", "dataset2.json"],
    output="merged_dataset.json"
)
```

## Dataset Management

### 1. Version Control

```python
from secauditai.datasets import DatasetManager

# Initialize manager
manager = DatasetManager()

# Create version
version = manager.create_version(
    dataset="custom_dataset.json",
    version="1.0.0",
    description="Initial version"
)

# Get version history
history = manager.get_version_history("custom_dataset.json")
```

### 2. Dataset Updates

```python
# Check for updates
updates = manager.check_updates("custom_dataset.json")

# Apply updates
manager.apply_updates(
    dataset="custom_dataset.json",
    updates=updates
)
```

### 3. Dataset Backup

```python
# Create backup
manager.create_backup(
    dataset="custom_dataset.json",
    location="backups/"
)

# Restore from backup
manager.restore_backup(
    dataset="custom_dataset.json",
    backup="backups/custom_dataset_20230101.json"
)
```

## Best Practices

1. **Data Quality**
   - Validate all entries
   - Use consistent formats
   - Include references

2. **Organization**
   - Use clear naming
   - Maintain version history
   - Document changes

3. **Security**
   - Protect sensitive data
   - Use secure storage
   - Control access

4. **Maintenance**
   - Regular updates
   - Remove duplicates
   - Archive old versions

## Troubleshooting

1. **Data Issues**
   - Check format
   - Validate entries
   - Fix inconsistencies

2. **Performance Issues**
   - Optimize queries
   - Use indexing
   - Cache results

3. **Access Issues**
   - Check permissions
   - Verify credentials
   - Test connections 