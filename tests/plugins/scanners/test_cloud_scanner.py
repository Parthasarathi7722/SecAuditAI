#!/usr/bin/env python3
"""
Tests for the cloud security scanner module.
"""
import pytest
from unittest.mock import patch, MagicMock
from secauditai.plugins.scanners.cloud_scanner import CloudScanner
import json
import subprocess

@pytest.fixture
def cloud_scanner():
    return CloudScanner()

def test_cloud_scanner_initialization(cloud_scanner):
    assert cloud_scanner.name == "cloud_scanner"
    assert cloud_scanner.description == "Cloud and Kubernetes security assessment using Prowler"
    assert set(cloud_scanner.supported_providers) == {"aws", "azure", "gcp", "kubernetes"}

@patch("subprocess.run")
def test_scan_cloud_aws(mock_run, cloud_scanner):
    # Mock Prowler output
    mock_output = {
        "summary": {
            "total_checks": 100,
            "passed": 80,
            "failed": 20
        },
        "findings": [
            {
                "check_id": "check1",
                "status": "FAIL",
                "severity": "HIGH",
                "title": "Test Finding",
                "description": "Test Description",
                "remediation": "Test Remediation",
                "resource_id": "resource1",
                "region": "us-east-1"
            }
        ]
    }
    mock_run.return_value = MagicMock(stdout=json.dumps(mock_output))
    
    result = cloud_scanner.scan_cloud("aws", region="us-east-1")
    
    assert result["provider"] == "aws"
    assert result["region"] == "us-east-1"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["check_id"] == "check1"
    assert result["findings"][0]["severity"] == "HIGH"

@patch("subprocess.run")
def test_scan_kubernetes(mock_run, cloud_scanner):
    # Mock Prowler output
    mock_output = {
        "summary": {
            "total_checks": 50,
            "passed": 45,
            "failed": 5
        },
        "findings": [
            {
                "check_id": "k8s-check1",
                "status": "FAIL",
                "severity": "MEDIUM",
                "title": "K8s Test Finding",
                "description": "K8s Test Description",
                "remediation": "K8s Test Remediation",
                "resource_id": "pod1",
                "namespace": "default"
            }
        ]
    }
    mock_run.return_value = MagicMock(stdout=json.dumps(mock_output))
    
    result = cloud_scanner.scan_kubernetes("test-cluster", namespace="default")
    
    assert result["cluster"] == "test-cluster"
    assert result["namespace"] == "default"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["check_id"] == "k8s-check1"
    assert result["findings"][0]["severity"] == "MEDIUM"

@patch("subprocess.run")
def test_generate_compliance_report(mock_run, cloud_scanner):
    # Mock Prowler output
    mock_output = {
        "summary": {
            "framework": "cis",
            "version": "1.4",
            "total_requirements": 100
        },
        "requirements": [
            {
                "id": "req1",
                "description": "Test Requirement",
                "status": "PASS"
            }
        ]
    }
    mock_run.return_value = MagicMock(stdout=json.dumps(mock_output))
    
    result = cloud_scanner.generate_compliance_report("aws", "cis")
    
    assert result["framework"] == "cis"
    assert len(result["requirements"]) == 1
    assert result["requirements"][0]["id"] == "req1"
    assert result["requirements"][0]["status"] == "PASS"

def test_scan_invalid_target(cloud_scanner):
    with pytest.raises(ValueError, match="Unsupported target"):
        cloud_scanner.scan("invalid_target")

@patch("subprocess.run")
def test_scan_cloud_error_handling(mock_run, cloud_scanner):
    mock_run.side_effect = subprocess.CalledProcessError(1, "prowler", "Test error")
    
    with pytest.raises(subprocess.CalledProcessError):
        cloud_scanner.scan_cloud("aws")

@patch("subprocess.run")
def test_scan_kubernetes_error_handling(mock_run, cloud_scanner):
    mock_run.side_effect = json.JSONDecodeError("Test error", "invalid json", 0)
    
    with pytest.raises(json.JSONDecodeError):
        cloud_scanner.scan_kubernetes("test-cluster") 