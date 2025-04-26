#!/usr/bin/env python3
"""
Basic SecAuditAI Scan Example
This example demonstrates how to perform a basic security scan using SecAuditAI.
"""

from secauditai import Client

def main():
    # Initialize the client
    client = Client(api_key="your-api-key")
    
    # Example 1: Scan a local repository
    print("Scanning local repository...")
    results = client.scan_code(
        repository="path/to/your/repo",
        options={
            "languages": ["python", "javascript"],
            "depth": 3,
            "exclude": ["tests/", "docs/"]
        }
    )
    print(f"Scan results: {results}")
    
    # Example 2: Scan AWS infrastructure
    print("\nScanning AWS infrastructure...")
    aws_results = client.scan_aws(
        profile="default",
        regions=["us-east-1"],
        services=["ec2", "s3"]
    )
    print(f"AWS scan results: {aws_results}")
    
    # Example 3: Generate and analyze SBOM
    print("\nGenerating SBOM...")
    sbom = client.sbom_generate(
        project_path="path/to/project",
        format="spdx"
    )
    print(f"SBOM generated: {sbom}")
    
    # Analyze SBOM for vulnerabilities
    print("\nAnalyzing SBOM for vulnerabilities...")
    analysis = client.sbom_analyze(
        sbom_id=sbom["id"],
        vulnerability_check=True
    )
    print(f"SBOM analysis results: {analysis}")

if __name__ == "__main__":
    main() 