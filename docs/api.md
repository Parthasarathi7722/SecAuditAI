# API Reference

## Overview

SecAuditAI provides a comprehensive API for security auditing and analysis. This document details all available endpoints, parameters, and response formats.

## Authentication

```bash
# Set API key
export SECAUDITAI_API_KEY=your_api_key

# Or use in requests
curl -H "Authorization: Bearer $SECAUDITAI_API_KEY" ...
```

## Core Endpoints

### 1. Code Analysis

```bash
# Scan code repository
POST /api/v1/scan/code
{
    "repository": "path/to/repo",
    "options": {
        "languages": ["python", "javascript"],
        "depth": 3,
        "exclude": ["tests/", "docs/"]
    }
}

# Get scan results
GET /api/v1/scan/code/{scan_id}
```

### 2. Cloud Infrastructure

```bash
# AWS Scan
POST /api/v1/scan/aws
{
    "profile": "default",
    "regions": ["us-east-1", "us-west-2"],
    "services": ["ec2", "s3", "rds"]
}

# Azure Scan
POST /api/v1/scan/azure
{
    "subscription_id": "your-subscription-id",
    "resource_groups": ["prod", "staging"]
}

# GCP Scan
POST /api/v1/scan/gcp
{
    "project_id": "your-project-id",
    "regions": ["us-central1", "europe-west1"]
}
```

### 3. SBOM Analysis

```bash
# Generate SBOM
POST /api/v1/sbom/generate
{
    "project_path": "path/to/project",
    "format": "spdx",
    "include_dev": false
}

# Analyze SBOM
POST /api/v1/sbom/analyze
{
    "sbom_id": "sbom-123",
    "vulnerability_check": true
}
```

### 4. Compliance Checks

```bash
# Run compliance check
POST /api/v1/compliance/check
{
    "provider": "aws",
    "framework": "cis",
    "version": "1.4",
    "profile": "default"
}
```

## AI Model Endpoints

### 1. Vulnerability Detection

```bash
# Detect vulnerabilities
POST /api/v1/ai/vulnerability/detect
{
    "code": "your code here",
    "language": "python",
    "model": "codebert"
}

# Get detection results
GET /api/v1/ai/vulnerability/results/{detection_id}
```

### 2. Security Analysis

```bash
# Analyze security posture
POST /api/v1/ai/security/analyze
{
    "data": {
        "configurations": [...],
        "logs": [...],
        "metrics": [...]
    },
    "model": "securitybert"
}
```

## Webhook Integration

```bash
# Configure webhook
POST /api/v1/webhooks
{
    "url": "https://your-webhook-url",
    "events": ["vulnerability_detected", "compliance_violation"],
    "secret": "your-webhook-secret"
}
```

## Response Formats

### Success Response
```json
{
    "status": "success",
    "data": {
        "id": "request-id",
        "timestamp": "2024-03-20T12:00:00Z",
        "results": {...}
    }
}
```

### Error Response
```json
{
    "status": "error",
    "error": {
        "code": "ERROR_CODE",
        "message": "Error description",
        "details": {...}
    }
}
```

## Rate Limits

- Free tier: 100 requests/hour
- Pro tier: 1000 requests/hour
- Enterprise: Custom limits

## SDKs

### Python
```python
from secauditai import Client

client = Client(api_key="your-api-key")
results = client.scan_code("path/to/repo")
```

### JavaScript
```javascript
const SecAuditAI = require('secauditai');

const client = new SecAuditAI.Client({
    apiKey: 'your-api-key'
});

client.scanCode('path/to/repo')
    .then(results => console.log(results));
```

## Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 429 | Too Many Requests |
| 500 | Internal Server Error |

## Versioning

API version is specified in the URL path: `/api/v1/...`

## Support

For API support, contact: api-support@secauditai.com 