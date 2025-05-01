#!/usr/bin/env python3
"""
Multi-Cloud Scanning Example
-------------------
This example demonstrates how to use SecAuditAI for multi-cloud security scanning.
"""

from secauditai import SecAuditAI
import json

def main():
    # Initialize scanner
    scanner = SecAuditAI()
    
    # Example 1: Multi-cloud scan with AWS and Azure
    print("Running multi-cloud scan (AWS + Azure)...")
    results = scanner.scan_multi_cloud(
        providers=["aws", "azure"],
        config={
            "aws": {
                "profile": "default",
                "regions": ["us-east-1", "us-west-2"],
                "services": ["ec2", "s3", "rds"]
            },
            "azure": {
                "subscription_id": "your-subscription-id",
                "resource_groups": ["prod", "staging"],
                "services": ["compute", "storage", "network"]
            }
        }
    )
    print(json.dumps(results, indent=2))
    
    # Example 2: Multi-cloud scan with AWS, Azure, and GCP
    print("\nRunning multi-cloud scan (AWS + Azure + GCP)...")
    results = scanner.scan_multi_cloud(
        providers=["aws", "azure", "gcp"],
        config={
            "aws": {
                "profile": "default",
                "regions": ["us-east-1", "us-west-2"]
            },
            "azure": {
                "subscription_id": "your-subscription-id",
                "resource_groups": ["prod", "staging"]
            },
            "gcp": {
                "project_id": "your-project-id",
                "regions": ["us-central1", "europe-west1"]
            }
        }
    )
    print(json.dumps(results, indent=2))
    
    # Example 3: Multi-cloud scan with custom rules
    print("\nRunning multi-cloud scan with custom rules...")
    rule = {
        "id": "multi-cloud-001",
        "name": "Cross-Cloud Access",
        "description": "Detects cross-cloud access patterns",
        "severity": "high",
        "confidence": 0.9
    }
    scanner.add_rule(rule)
    
    results = scanner.scan_multi_cloud(
        providers=["aws", "azure", "gcp"],
        rules=["multi-cloud-001"],
        severity="high"
    )
    print(json.dumps(results, indent=2))
    
    # Example 4: Multi-cloud scan with specific services
    print("\nRunning multi-cloud scan with specific services...")
    results = scanner.scan_multi_cloud(
        providers=["aws", "azure", "gcp"],
        services={
            "aws": ["ec2", "s3"],
            "azure": ["compute", "storage"],
            "gcp": ["compute", "storage"]
        }
    )
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 