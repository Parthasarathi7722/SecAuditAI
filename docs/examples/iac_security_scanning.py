#!/usr/bin/env python3
"""
IAC Security Scanning Example
-------------------
This example demonstrates how to use SecAuditAI for Infrastructure as Code security scanning
with multiple tools (Terraform, Checkov, TFSec).
"""

from secauditai import SecAuditAI
import json
import subprocess
import os

def run_checkov(terraform_dir):
    """Run Checkov security scan"""
    try:
        result = subprocess.run(
            ["checkov", "-d", terraform_dir, "--output", "json"],
            capture_output=True,
            text=True
        )
        return json.loads(result.stdout)
    except Exception as e:
        print(f"Error running Checkov: {e}")
        return None

def run_tfsec(terraform_dir):
    """Run TFSec security scan"""
    try:
        result = subprocess.run(
            ["tfsec", terraform_dir, "--format", "json"],
            capture_output=True,
            text=True
        )
        return json.loads(result.stdout)
    except Exception as e:
        print(f"Error running TFSec: {e}")
        return None

def main():
    # Initialize scanner
    scanner = SecAuditAI()
    
    # Example 1: Basic Terraform scan
    print("Running basic Terraform scan...")
    results = scanner.scan_terraform(
        directory="path/to/terraform",
        check_variables=True,
        check_resources=True,
        check_modules=True
    )
    print(json.dumps(results, indent=2))
    
    # Example 2: Multi-tool IAC scan
    print("\nRunning multi-tool IAC scan...")
    terraform_dir = "path/to/terraform"
    
    # Run Checkov
    print("Running Checkov scan...")
    checkov_results = run_checkov(terraform_dir)
    if checkov_results:
        print("Checkov findings:", json.dumps(checkov_results, indent=2))
    
    # Run TFSec
    print("\nRunning TFSec scan...")
    tfsec_results = run_tfsec(terraform_dir)
    if tfsec_results:
        print("TFSec findings:", json.dumps(tfsec_results, indent=2))
    
    # Example 3: Custom IAC rules
    print("\nRunning scan with custom IAC rules...")
    custom_rules = [
        {
            "id": "iac-001",
            "name": "Secure Storage Configuration",
            "description": "Ensures secure storage configurations",
            "severity": "high",
            "patterns": [
                "resource.*aws_s3_bucket.*public_access_block",
                "resource.*azurerm_storage_account.*network_rules"
            ]
        }
    ]
    
    results = scanner.scan_terraform(
        directory=terraform_dir,
        custom_rules=custom_rules,
        severity="high"
    )
    print(json.dumps(results, indent=2))
    
    # Example 4: CI/CD Integration
    print("\nRunning CI/CD integrated scan...")
    results = scanner.scan_terraform(
        directory=terraform_dir,
        ci_cd=True,
        fail_on_high=True,
        output_format="sarif"
    )
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 