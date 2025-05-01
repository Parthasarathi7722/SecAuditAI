#!/usr/bin/env python3
"""
API Security Scanning Example
-------------------
This example demonstrates how to use SecAuditAI for API security scanning.
"""

from secauditai import SecAuditAI
import json

def main():
    # Initialize scanner
    scanner = SecAuditAI()
    
    # Example 1: Basic API scan
    print("Running basic API security scan...")
    results = scanner.test_api(
        url="https://api.example.com",
        check_auth=True,
        check_input_validation=True,
        check_rate_limiting=True
    )
    print(json.dumps(results, indent=2))
    
    # Example 2: OpenAPI specification scan
    print("\nRunning OpenAPI specification scan...")
    results = scanner.test_openapi(
        spec="path/to/openapi.yaml",
        check_security_schemes=True,
        check_parameters=True,
        check_responses=True
    )
    print(json.dumps(results, indent=2))
    
    # Example 3: GraphQL API scan
    print("\nRunning GraphQL API security scan...")
    results = scanner.test_graphql(
        url="https://api.example.com/graphql",
        schema="path/to/schema.graphql",
        check_introspection=True,
        check_query_complexity=True
    )
    print(json.dumps(results, indent=2))
    
    # Example 4: gRPC API scan
    print("\nRunning gRPC API security scan...")
    results = scanner.test_grpc(
        proto="path/to/service.proto",
        host="api.example.com",
        port=50051,
        check_authentication=True,
        check_authorization=True
    )
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 