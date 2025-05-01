#!/usr/bin/env python3
"""
Custom Rules Example
------------------
This example demonstrates how to create and use custom security rules
with SecAuditAI.
"""

from secauditai import RuleEngine
from secauditai.reports import generate_rule_report

def main():
    # Initialize rule engine
    engine = RuleEngine()
    
    # Create custom rules
    print("Creating custom rules...")
    
    # Example 1: Custom code security rule
    code_rule = engine.create_rule(
        name="custom_code_security",
        type="code",
        description="Check for custom security patterns in code",
        pattern="""
        # Check for hardcoded credentials
        if re.search(r'password\s*=\s*["\'].*["\']', code):
            return True
        
        # Check for debug statements
        if re.search(r'console\.log|print\(|debugger', code):
            return True
        """,
        severity="high"
    )
    
    # Example 2: Custom cloud security rule
    cloud_rule = engine.create_rule(
        name="custom_cloud_security",
        type="cloud",
        description="Check for custom cloud security configurations",
        pattern="""
        # Check for public S3 buckets
        if bucket['PublicAccessBlockConfiguration'] is None:
            return True
        
        # Check for unrestricted security groups
        if security_group['IpPermissions']:
            for permission in security_group['IpPermissions']:
                if permission['IpRanges'][0]['CidrIp'] == '0.0.0.0/0':
                    return True
        """,
        severity="critical"
    )
    
    # Example 3: Custom container security rule
    container_rule = engine.create_rule(
        name="custom_container_security",
        type="container",
        description="Check for custom container security settings",
        pattern="""
        # Check for root user
        if container['User'] == 'root':
            return True
        
        # Check for privileged mode
        if container['Privileged']:
            return True
        """,
        severity="medium"
    )
    
    # Register rules
    engine.register_rule(code_rule)
    engine.register_rule(cloud_rule)
    engine.register_rule(container_rule)
    
    # Run rules against targets
    print("\nRunning custom rules...")
    results = engine.run_rules(
        targets=[
            {"type": "code", "path": "/path/to/code"},
            {"type": "cloud", "provider": "aws", "region": "us-east-1"},
            {"type": "container", "image": "nginx:latest"}
        ]
    )
    
    # Generate report
    report = generate_rule_report(
        results=results,
        format="html"
    )
    
    # Save report
    with open("custom_rules_report.html", "w") as f:
        f.write(report)
    
    print("\nCustom rules report generated: custom_rules_report.html")

if __name__ == "__main__":
    main() 