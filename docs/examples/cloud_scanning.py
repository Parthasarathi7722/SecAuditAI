#!/usr/bin/env python3
"""
Cloud Scanning Example
--------------------
This example demonstrates how to use SecAuditAI for scanning cloud infrastructure
across multiple providers (AWS, Azure, GCP).
"""

from secauditai import CloudScanner
from secauditai.reports import generate_cloud_report

def main():
    # Initialize cloud scanner
    scanner = CloudScanner()
    
    # AWS Scanning
    print("Scanning AWS infrastructure...")
    aws_results = scanner.scan_aws(
        profile="default",
        regions=["us-east-1", "us-west-2"],
        services=["ec2", "s3", "rds"]
    )
    
    # Azure Scanning
    print("\nScanning Azure infrastructure...")
    azure_results = scanner.scan_azure(
        subscription_id="your-subscription-id",
        resource_groups=["prod-rg", "dev-rg"]
    )
    
    # GCP Scanning
    print("\nScanning GCP infrastructure...")
    gcp_results = scanner.scan_gcp(
        project_id="your-project-id",
        regions=["us-central1", "europe-west1"]
    )
    
    # Generate comprehensive report
    report = generate_cloud_report(
        aws_results=aws_results,
        azure_results=azure_results,
        gcp_results=gcp_results,
        format="html"
    )
    
    # Save report
    with open("cloud_security_report.html", "w") as f:
        f.write(report)
    
    print("\nCloud security report generated: cloud_security_report.html")

if __name__ == "__main__":
    main() 