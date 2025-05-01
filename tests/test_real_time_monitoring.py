#!/usr/bin/env python3
"""
Tests for Real-time Monitoring
----------------------------
This module contains tests for the real-time security monitoring feature.
"""

import pytest
import time
from secauditai import RealTimeMonitor
from secauditai.notifications import SlackNotifier, WebhookNotifier

class TestRealTimeMonitoring:
    @pytest.fixture
    def monitor(self):
        monitor = RealTimeMonitor()
        monitor.enable_experimental()
        return monitor
    
    @pytest.fixture
    def notifiers(self):
        return [
            SlackNotifier(webhook_url="test-url", channel="#test"),
            WebhookNotifier(url="test-url", secret="test-secret")
        ]
    
    def test_monitor_initialization(self, monitor):
        """Test monitor initialization and configuration."""
        assert monitor.is_experimental_enabled() is True
        assert monitor.get_check_interval() == 60
        assert monitor.get_alert_threshold() == 0.8
    
    def test_notifier_registration(self, monitor, notifiers):
        """Test notifier registration and configuration."""
        for notifier in notifiers:
            monitor.add_notifier(notifier)
        
        assert len(monitor.get_notifiers()) == len(notifiers)
    
    def test_monitoring_configuration(self, monitor):
        """Test monitoring configuration."""
        monitor.configure(
            check_interval=30,
            alert_threshold=0.9,
            max_alerts_per_hour=5
        )
        
        assert monitor.get_check_interval() == 30
        assert monitor.get_alert_threshold() == 0.9
        assert monitor.get_max_alerts_per_hour() == 5
    
    def test_target_monitoring(self, monitor):
        """Test monitoring of different target types."""
        targets = [
            {"type": "cloud", "provider": "aws", "region": "us-east-1"},
            {"type": "container", "id": "test-container"},
            {"type": "network", "interface": "eth0"}
        ]
        
        monitor.start(targets=targets, duration=5)
        time.sleep(1)  # Allow some monitoring time
        monitor.stop()
        
        metrics = monitor.get_metrics()
        assert isinstance(metrics, dict)
        assert all(target["type"] in metrics for target in targets)
    
    def test_alert_generation(self, monitor, notifiers):
        """Test alert generation and notification."""
        for notifier in notifiers:
            monitor.add_notifier(notifier)
        
        monitor.configure(alert_threshold=0.5)  # Lower threshold for testing
        
        # Simulate security event
        monitor._simulate_event(severity="high")
        
        alerts = monitor.get_alerts()
        assert len(alerts) > 0
        assert alerts[0]["severity"] == "high"
    
    def test_report_generation(self, monitor):
        """Test monitoring report generation."""
        monitor.start(
            targets=[{"type": "cloud", "provider": "aws"}],
            duration=5
        )
        time.sleep(1)
        monitor.stop()
        
        report = monitor.generate_report(
            format="html",
            include_metrics=True,
            include_alerts=True
        )
        
        assert isinstance(report, str)
        assert "<html" in report.lower()
    
    def test_error_handling(self, monitor):
        """Test error handling in monitoring."""
        with pytest.raises(ValueError):
            monitor.start(targets=[{"type": "invalid"}])
        
        with pytest.raises(ValueError):
            monitor.configure(check_interval=-1)
    
    def test_resource_usage(self, monitor):
        """Test resource usage during monitoring."""
        import psutil
        import time
        
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        monitor.start(
            targets=[{"type": "cloud", "provider": "aws"}],
            duration=5
        )
        time.sleep(1)
        
        current_memory = process.memory_info().rss
        memory_increase = current_memory - initial_memory
        
        monitor.stop()
        
        assert memory_increase < 100 * 1024 * 1024  # Less than 100MB increase 