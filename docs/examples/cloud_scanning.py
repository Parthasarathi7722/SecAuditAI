#!/usr/bin/env python3
"""
Cloud Scanning Example
-------------------
This example demonstrates how to use SecAuditAI for cloud security scanning.
"""

from secauditai import SecAuditAI
import json

def main():
    # Initialize scanner
    scanner = SecAuditAI()
    
    # Example 1: AWS scan
    print("Running AWS security scan...")
    results = scanner.scan_cloud(
        provider="aws",
        profile="default",
        regions=["us-east-1", "us-west-2"],
        services=["ec2", "s3", "rds"]
    )
    print(json.dumps(results, indent=2))
    
    # Example 2: Azure scan
    print("\nRunning Azure security scan...")
    results = scanner.scan_cloud(
        provider="azure",
        subscription_id="your-subscription-id",
        resource_groups=["prod", "staging"]
    )
    print(json.dumps(results, indent=2))
    
    # Example 3: GCP scan
    print("\nRunning GCP security scan...")
    results = scanner.scan_cloud(
        provider="gcp",
        project_id="your-project-id",
        regions=["us-central1", "europe-west1"]
    )
    print(json.dumps(results, indent=2))
    
    # Example 4: Multi-cloud scan
    print("\nRunning multi-cloud security scan...")
    results = scanner.scan_cloud(
        providers=["aws", "azure", "gcp"],
        config={
            "aws": {"profile": "default"},
            "azure": {"subscription_id": "your-subscription-id"},
            "gcp": {"project_id": "your-project-id"}
        }
    )
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 