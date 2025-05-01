#!/usr/bin/env python3
"""
Tests for Experimental Features
-----------------------------
This module contains tests for experimental features in SecAuditAI.
"""

import pytest
from secauditai import (
    ZeroDayScanner,
    RealTimeMonitor,
    SBOMGenerator,
    ComplianceChecker
)

class TestExperimentalFeatures:
    @pytest.fixture
    def zero_day_scanner(self):
        scanner = ZeroDayScanner()
        scanner.enable_experimental()
        return scanner
    
    @pytest.fixture
    def real_time_monitor(self):
        monitor = RealTimeMonitor()
        monitor.enable_experimental()
        return monitor
    
    @pytest.fixture
    def sbom_generator(self):
        generator = SBOMGenerator()
        generator.enable_experimental()
        return generator
    
    @pytest.fixture
    def compliance_checker(self):
        checker = ComplianceChecker()
        checker.enable_experimental()
        return checker
    
    def test_feature_enablement(self, zero_day_scanner, real_time_monitor, sbom_generator, compliance_checker):
        """Test experimental feature enablement."""
        assert zero_day_scanner.is_experimental_enabled() is True
        assert real_time_monitor.is_experimental_enabled() is True
        assert sbom_generator.is_experimental_enabled() is True
        assert compliance_checker.is_experimental_enabled() is True
    
    def test_zero_day_detection(self, zero_day_scanner):
        """Test zero-day detection experimental features."""
        results = zero_day_scanner.scan_code(
            path="tests/test_data/code",
            languages=["python"],
            check_patterns=True,
            check_behavior=True
        )
        assert isinstance(results, dict)
        assert "experimental_results" in results
    
    def test_real_time_monitoring(self, real_time_monitor):
        """Test real-time monitoring experimental features."""
        real_time_monitor.configure(
            check_interval=30,
            alert_threshold=0.9,
            max_alerts_per_hour=5
        )
        assert real_time_monitor.get_check_interval() == 30
        assert real_time_monitor.get_alert_threshold() == 0.9
    
    def test_sbom_generation(self, sbom_generator):
        """Test SBOM generation experimental features."""
        sbom = sbom_generator.generate(
            path="tests/test_data/project",
            format="spdx",
            include_dependencies=True,
            include_licenses=True
        )
        assert isinstance(sbom, dict)
        assert "experimental_metadata" in sbom
    
    def test_compliance_checks(self, compliance_checker):
        """Test compliance checks experimental features."""
        results = compliance_checker.check_cis(
            framework="cis-1.5",
            level=2,
            sections=["1", "2", "3"]
        )
        assert isinstance(results, dict)
        assert "experimental_findings" in results
    
    def test_performance_impact(self, zero_day_scanner, real_time_monitor):
        """Test performance impact of experimental features."""
        import time
        
        # Test zero-day scanner performance
        start_time = time.time()
        zero_day_scanner.scan_code(
            path="tests/test_data/code",
            languages=["python"]
        )
        zero_day_duration = time.time() - start_time
        
        # Test real-time monitor performance
        start_time = time.time()
        real_time_monitor.start(
            targets=[{"type": "cloud", "provider": "aws"}],
            duration=5
        )
        time.sleep(1)
        real_time_monitor.stop()
        monitor_duration = time.time() - start_time
        
        assert zero_day_duration < 10  # Less than 10 seconds
        assert monitor_duration < 15  # Less than 15 seconds
    
    def test_error_handling(self, zero_day_scanner, real_time_monitor):
        """Test error handling in experimental features."""
        with pytest.raises(ValueError):
            zero_day_scanner.scan_code(
                path="nonexistent/path",
                languages=["python"]
            )
        
        with pytest.raises(ValueError):
            real_time_monitor.start(
                targets=[{"type": "invalid"}]
            )
    
    def test_feature_disabling(self, zero_day_scanner, real_time_monitor):
        """Test experimental feature disabling."""
        zero_day_scanner.disable_experimental()
        real_time_monitor.disable_experimental()
        
        assert zero_day_scanner.is_experimental_enabled() is False
        assert real_time_monitor.is_experimental_enabled() is False
        
        # Re-enable for other tests
        zero_day_scanner.enable_experimental()
        real_time_monitor.enable_experimental() 