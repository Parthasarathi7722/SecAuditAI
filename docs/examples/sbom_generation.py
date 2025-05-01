#!/usr/bin/env python3
"""
SBOM Generation Example
---------------------
This example demonstrates how to use SecAuditAI for generating and analyzing
Software Bill of Materials (SBOM) for your projects.
"""

from secauditai import SBOMGenerator
from secauditai.reports import generate_sbom_report

def main():
    # Initialize SBOM generator
    generator = SBOMGenerator()
    
    # Generate SBOM for a project
    print("Generating SBOM for project...")
    sbom = generator.generate(
        path="/path/to/project",
        format="spdx",  # Options: spdx, cyclonedx, swid
        include_dependencies=True,
        include_licenses=True,
        include_vulnerabilities=True
    )
    
    # Analyze SBOM for vulnerabilities
    print("\nAnalyzing SBOM for vulnerabilities...")
    analysis = generator.analyze(
        sbom=sbom,
        check_cves=True,
        check_licenses=True,
        check_dependencies=True
    )
    
    # Generate comprehensive report
    report = generate_sbom_report(
        sbom=sbom,
        analysis=analysis,
        format="html"
    )
    
    # Save report
    with open("sbom_report.html", "w") as f:
        f.write(report)
    
    # Export SBOM in different formats
    generator.export(sbom, "sbom.spdx", format="spdx")
    generator.export(sbom, "sbom.cyclonedx.json", format="cyclonedx")
    
    print("\nSBOM report generated: sbom_report.html")
    print("SBOM exported in SPDX and CycloneDX formats")

if __name__ == "__main__":
    main() 