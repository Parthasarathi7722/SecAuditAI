#!/usr/bin/env python3
"""
Container Scanning Example
-------------------
This example demonstrates how to use SecAuditAI for container security scanning.
"""

from secauditai import SecAuditAI
import json

def main():
    # Initialize scanner
    scanner = SecAuditAI()
    
    # Example 1: Docker image scan
    print("Running Docker image scan...")
    results = scanner.scan_container(
        image="your-image:tag",
        check_vulnerabilities=True,
        check_misconfigurations=True
    )
    print(json.dumps(results, indent=2))
    
    # Example 2: Kubernetes cluster scan
    print("\nRunning Kubernetes cluster scan...")
    results = scanner.scan_kubernetes(
        namespace="your-namespace",
        check_pods=True,
        check_services=True,
        check_ingress=True
    )
    print(json.dumps(results, indent=2))
    
    # Example 3: Container runtime scan
    print("\nRunning container runtime scan...")
    results = scanner.scan_runtime(
        container_id="container-id",
        check_processes=True,
        check_network=True,
        check_filesystem=True
    )
    print(json.dumps(results, indent=2))
    
    # Example 4: Container registry scan
    print("\nRunning container registry scan...")
    results = scanner.scan_registry(
        registry="your-registry",
        repository="your-repository",
        tag="latest"
    )
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 