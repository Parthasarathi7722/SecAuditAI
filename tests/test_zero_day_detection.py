#!/usr/bin/env python3
"""
Tests for Zero-Day Detection
---------------------------
This module contains tests for the zero-day vulnerability detection feature.
"""

import pytest
from secauditai import ZeroDayScanner
from secauditai.reports import generate_zero_day_report

class TestZeroDayDetection:
    @pytest.fixture
    def scanner(self):
        scanner = ZeroDayScanner()
        scanner.enable_experimental()
        return scanner
    
    def test_code_scanning(self, scanner):
        """Test code scanning for zero-day vulnerabilities."""
        results = scanner.scan_code(
            path="tests/test_data/code",
            languages=["python"],
            check_patterns=True
        )
        assert isinstance(results, dict)
        assert "vulnerabilities" in results
        assert "patterns" in results
    
    def test_network_analysis(self, scanner):
        """Test network traffic analysis for zero-day vulnerabilities."""
        results = scanner.analyze_network(
            pcap_file="tests/test_data/network.pcap",
            duration=60,
            check_protocols=True
        )
        assert isinstance(results, dict)
        assert "anomalies" in results
        assert "protocols" in results
    
    def test_report_generation(self, scanner):
        """Test zero-day detection report generation."""
        code_results = scanner.scan_code(
            path="tests/test_data/code",
            languages=["python"]
        )
        network_results = scanner.analyze_network(
            pcap_file="tests/test_data/network.pcap",
            duration=60
        )
        
        report = generate_zero_day_report(
            code_results=code_results,
            network_results=network_results,
            format="html"
        )
        assert isinstance(report, str)
        assert "<html" in report.lower()
    
    def test_experimental_features(self, scanner):
        """Test experimental feature configuration."""
        assert scanner.is_experimental_enabled() is True
        
        scanner.disable_experimental()
        assert scanner.is_experimental_enabled() is False
        
        scanner.enable_experimental()
        assert scanner.is_experimental_enabled() is True
    
    def test_performance(self, scanner):
        """Test performance of zero-day detection."""
        import time
        
        start_time = time.time()
        scanner.scan_code(
            path="tests/test_data/code",
            languages=["python"],
            check_patterns=True,
            check_behavior=True
        )
        duration = time.time() - start_time
        
        assert duration < 10  # Should complete within 10 seconds
    
    def test_error_handling(self, scanner):
        """Test error handling in zero-day detection."""
        with pytest.raises(ValueError):
            scanner.scan_code(
                path="nonexistent/path",
                languages=["python"]
            )
        
        with pytest.raises(FileNotFoundError):
            scanner.analyze_network(
                pcap_file="nonexistent.pcap",
                duration=60
            ) 