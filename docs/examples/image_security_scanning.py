#!/usr/bin/env python3
"""
Container Image Security Scanning Example
-------------------
This example demonstrates how to use SecAuditAI for container image security scanning
with multiple tools (Trivy, Clair, Anchore).
"""

from secauditai import SecAuditAI
import json
import subprocess
import os
import docker
from datetime import datetime

def run_trivy(image_name):
    """Run Trivy security scan"""
    try:
        result = subprocess.run(
            ["trivy", "image", "--format", "json", image_name],
            capture_output=True,
            text=True
        )
        return json.loads(result.stdout)
    except Exception as e:
        print(f"Error running Trivy: {e}")
        return None

def run_clair(image_name):
    """Run Clair security scan"""
    try:
        # Save image to tar
        client = docker.from_env()
        image = client.images.get(image_name)
        tar_path = f"/tmp/{image_name.replace('/', '_')}.tar"
        with open(tar_path, 'wb') as f:
            for chunk in image.save():
                f.write(chunk)
        
        # Run Clair scan
        result = subprocess.run(
            ["clair-scanner", "--ip", "localhost", "--report", "clair_report.json", tar_path],
            capture_output=True,
            text=True
        )
        
        # Clean up
        os.remove(tar_path)
        
        if os.path.exists("clair_report.json"):
            with open("clair_report.json", "r") as f:
                return json.load(f)
        return None
    except Exception as e:
        print(f"Error running Clair: {e}")
        return None

def run_anchore(image_name):
    """Run Anchore security scan"""
    try:
        result = subprocess.run(
            ["anchore-cli", "image", "analyze", image_name],
            capture_output=True,
            text=True
        )
        
        # Get vulnerabilities
        vuln_result = subprocess.run(
            ["anchore-cli", "image", "vuln", image_name, "all"],
            capture_output=True,
            text=True
        )
        return {
            "analysis": result.stdout,
            "vulnerabilities": vuln_result.stdout
        }
    except Exception as e:
        print(f"Error running Anchore: {e}")
        return None

def main():
    # Initialize scanner
    scanner = SecAuditAI()
    
    # Example 1: Basic image scan
    print("Running basic image scan...")
    results = scanner.scan_image(
        image="nginx:latest",
        check_vulnerabilities=True,
        check_configuration=True,
        check_secrets=True
    )
    print(json.dumps(results, indent=2))
    
    # Example 2: Multi-tool image scan
    print("\nRunning multi-tool image scan...")
    image_name = "nginx:latest"
    
    # Run Trivy
    print("Running Trivy scan...")
    trivy_results = run_trivy(image_name)
    if trivy_results:
        print("Trivy findings:", json.dumps(trivy_results, indent=2))
    
    # Run Clair
    print("\nRunning Clair scan...")
    clair_results = run_clair(image_name)
    if clair_results:
        print("Clair findings:", json.dumps(clair_results, indent=2))
    
    # Run Anchore
    print("\nRunning Anchore scan...")
    anchore_results = run_anchore(image_name)
    if anchore_results:
        print("Anchore findings:", json.dumps(anchore_results, indent=2))
    
    # Example 3: Custom image rules
    print("\nRunning scan with custom image rules...")
    custom_rules = [
        {
            "id": "image-001",
            "name": "Secure Base Image",
            "description": "Ensures use of secure base images",
            "severity": "high",
            "patterns": [
                "FROM.*alpine:.*",
                "FROM.*debian:.*"
            ]
        },
        {
            "id": "image-002",
            "name": "No Root User",
            "description": "Ensures container doesn't run as root",
            "severity": "high",
            "patterns": [
                "USER root",
                "RUN.*useradd.*"
            ]
        }
    ]
    
    results = scanner.scan_image(
        image=image_name,
        custom_rules=custom_rules,
        severity="high"
    )
    print(json.dumps(results, indent=2))
    
    # Example 4: CI/CD Integration
    print("\nRunning CI/CD integrated scan...")
    results = scanner.scan_image(
        image=image_name,
        ci_cd=True,
        fail_on_high=True,
        output_format="sarif"
    )
    print(json.dumps(results, indent=2))
    
    # Example 5: Runtime Security
    print("\nRunning runtime security scan...")
    results = scanner.scan_image(
        image=image_name,
        runtime=True,
        check_processes=True,
        check_network=True,
        check_filesystem=True
    )
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 