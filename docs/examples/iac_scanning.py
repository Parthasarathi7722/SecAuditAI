#!/usr/bin/env python3
"""
Infrastructure as Code Scanning Example
-------------------
This example demonstrates how to use SecAuditAI for infrastructure as code security scanning.
"""

from secauditai import SecAuditAI
import json

def main():
    # Initialize scanner
    scanner = SecAuditAI()
    
    # Example 1: Terraform scan
    print("Running Terraform security scan...")
    results = scanner.scan_terraform(
        directory="path/to/terraform",
        check_variables=True,
        check_resources=True,
        check_modules=True
    )
    print(json.dumps(results, indent=2))
    
    # Example 2: CloudFormation scan
    print("\nRunning CloudFormation security scan...")
    results = scanner.scan_cloudformation(
        template="path/to/template.yaml",
        check_resources=True,
        check_parameters=True,
        check_outputs=True
    )
    print(json.dumps(results, indent=2))
    
    # Example 3: ARM template scan
    print("\nRunning ARM template security scan...")
    results = scanner.scan_arm(
        template="path/to/template.json",
        check_resources=True,
        check_parameters=True,
        check_variables=True
    )
    print(json.dumps(results, indent=2))
    
    # Example 4: Multi-IaC scan
    print("\nRunning multi-IaC security scan...")
    results = scanner.scan_iac(
        providers=["terraform", "cloudformation", "arm"],
        config={
            "terraform": {"directory": "path/to/terraform"},
            "cloudformation": {"template": "path/to/template.yaml"},
            "arm": {"template": "path/to/template.json"}
        }
    )
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 