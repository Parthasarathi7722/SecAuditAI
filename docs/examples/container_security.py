#!/usr/bin/env python3
"""
Container Security Example
------------------------
This example demonstrates how to use SecAuditAI for container security scanning,
including image analysis and runtime security monitoring.
"""

from secauditai import ContainerScanner
from secauditai.reports import generate_container_report

def main():
    # Initialize container scanner
    scanner = ContainerScanner()
    
    # Scan container image
    print("Scanning container image...")
    image_results = scanner.scan_image(
        image="nginx:latest",
        scan_type="full",  # Options: quick, full, deep
        check_vulnerabilities=True,
        check_secrets=True,
        check_configuration=True
    )
    
    # Monitor container runtime
    print("\nMonitoring container runtime...")
    runtime_results = scanner.monitor_runtime(
        container_id="container-id",
        duration=300,  # 5 minutes
        check_processes=True,
        check_network=True,
        check_filesystem=True
    )
    
    # Generate comprehensive report
    report = generate_container_report(
        image_results=image_results,
        runtime_results=runtime_results,
        format="html"
    )
    
    # Save report
    with open("container_security_report.html", "w") as f:
        f.write(report)
    
    print("\nContainer security report generated: container_security_report.html")

if __name__ == "__main__":
    main() 