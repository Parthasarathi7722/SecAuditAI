#!/usr/bin/env python3
"""
Hybrid Cloud Scanning Example
-------------------
This example demonstrates how to use SecAuditAI for hybrid cloud security scanning.
"""

from secauditai import SecAuditAI
import json

def main():
    # Initialize scanner
    scanner = SecAuditAI()
    
    # Example 1: Hybrid cloud scan with on-prem and AWS
    print("Running hybrid cloud scan (On-prem + AWS)...")
    results = scanner.scan_hybrid_cloud(
        environments=["on_prem", "aws"],
        config={
            "on_prem": {
                "servers": ["server1", "server2"],
                "networks": ["network1", "network2"],
                "services": ["web", "database"]
            },
            "aws": {
                "profile": "default",
                "regions": ["us-east-1"],
                "services": ["ec2", "s3"]
            }
        }
    )
    print(json.dumps(results, indent=2))
    
    # Example 2: Hybrid cloud scan with on-prem, AWS, and Azure
    print("\nRunning hybrid cloud scan (On-prem + AWS + Azure)...")
    results = scanner.scan_hybrid_cloud(
        environments=["on_prem", "aws", "azure"],
        config={
            "on_prem": {
                "servers": ["server1", "server2"],
                "networks": ["network1", "network2"]
            },
            "aws": {
                "profile": "default",
                "regions": ["us-east-1"]
            },
            "azure": {
                "subscription_id": "your-subscription-id",
                "resource_groups": ["prod"]
            }
        }
    )
    print(json.dumps(results, indent=2))
    
    # Example 3: Hybrid cloud scan with custom rules
    print("\nRunning hybrid cloud scan with custom rules...")
    rule = {
        "id": "hybrid-001",
        "name": "Cross-Environment Access",
        "description": "Detects access between on-prem and cloud environments",
        "severity": "high",
        "confidence": 0.9
    }
    scanner.add_rule(rule)
    
    results = scanner.scan_hybrid_cloud(
        environments=["on_prem", "aws", "azure"],
        rules=["hybrid-001"],
        severity="high"
    )
    print(json.dumps(results, indent=2))
    
    # Example 4: Hybrid cloud scan with specific components
    print("\nRunning hybrid cloud scan with specific components...")
    results = scanner.scan_hybrid_cloud(
        environments=["on_prem", "aws", "azure"],
        components={
            "on_prem": {
                "servers": ["server1"],
                "networks": ["network1"]
            },
            "aws": {
                "services": ["ec2", "s3"]
            },
            "azure": {
                "services": ["compute", "storage"]
            }
        }
    )
    print(json.dumps(results, indent=2))
    
    # Example 5: Hybrid cloud scan with connectivity checks
    print("\nRunning hybrid cloud scan with connectivity checks...")
    results = scanner.scan_hybrid_cloud(
        environments=["on_prem", "aws", "azure"],
        check_connectivity=True,
        check_security_groups=True,
        check_firewalls=True
    )
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 