#!/usr/bin/env python3
"""
Code Scanning Example
-------------------
This example demonstrates how to use SecAuditAI for code security scanning.
"""

from secauditai import SecAuditAI
import json

def main():
    # Initialize scanner
    scanner = SecAuditAI()
    
    # Example 1: Basic code scan
    print("Running basic code scan...")
    results = scanner.scan_code(
        path="path/to/repo",
        languages=["python", "javascript"],
        exclude=["tests/", "docs/"]
    )
    print(json.dumps(results, indent=2))
    
    # Example 2: Advanced scan with custom rules
    print("\nRunning advanced scan with custom rules...")
    rule = {
        "id": "custom-001",
        "name": "Custom SQL Injection",
        "pattern": "raw\s*\([^)]*\+",
        "description": "Detects raw SQL query construction",
        "severity": "high",
        "confidence": 0.9
    }
    scanner.add_rule(rule)
    
    results = scanner.scan_code(
        path="path/to/repo",
        rules=["custom-001"],
        severity="high",
        confidence=0.9
    )
    print(json.dumps(results, indent=2))
    
    # Example 3: Real-time monitoring
    print("\nSetting up real-time monitoring...")
    def alert_callback(finding):
        print(f"New security finding: {finding}")
    
    scanner.start_monitoring(
        path="path/to/monitor",
        interval=300,  # 5 minutes
        callback=alert_callback
    )

if __name__ == "__main__":
    main() 