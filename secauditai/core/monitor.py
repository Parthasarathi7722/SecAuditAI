import time
import logging
import threading
from typing import Dict, List, Any, Optional
from pathlib import Path
import requests
from datetime import datetime
from .config import Config

logger = logging.getLogger(__name__)

class Monitor:
    """Security monitoring system for continuous scanning."""
    
    def __init__(self):
        self.config = Config()
        self.running = False
        self.thread = None
        self.last_scan = None
        self.findings = []
    
    def start(self, config_path: Optional[str] = None) -> None:
        """Start the monitoring system."""
        if config_path:
            self._load_config(config_path)
        
        if self.running:
            logger.warning("Monitoring is already running")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop)
        self.thread.daemon = True
        self.thread.start()
        logger.info("Monitoring started")
    
    def stop(self) -> None:
        """Stop the monitoring system."""
        if not self.running:
            logger.warning("Monitoring is not running")
            return
        
        self.running = False
        if self.thread:
            self.thread.join()
        logger.info("Monitoring stopped")
    
    def status(self) -> Dict[str, Any]:
        """Get monitoring status."""
        return {
            "running": self.running,
            "last_scan": self.last_scan,
            "total_findings": len(self.findings),
            "config": self.config.get_monitoring_config()
        }
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self.running:
            try:
                self._run_scan()
                interval = self.config.get("monitoring.interval", 300)
                time.sleep(interval)
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                time.sleep(60)  # Wait before retrying
    
    def _run_scan(self) -> None:
        """Run security scan and process findings."""
        from ..plugins.scanners import (
            CodeScanner, SBOMScanner, CloudScanner,
            ContainerScanner, ComplianceScanner
        )
        
        scanners = [
            CodeScanner(),
            SBOMScanner(),
            CloudScanner(),
            ContainerScanner(),
            ComplianceScanner()
        ]
        
        new_findings = []
        for scanner in scanners:
            try:
                results = scanner.scan(".")
                if results and "findings" in results:
                    new_findings.extend(results["findings"])
            except Exception as e:
                logger.error(f"Scanner {scanner.name} failed: {e}")
        
        if new_findings:
            self._process_findings(new_findings)
        
        self.last_scan = datetime.now().isoformat()
    
    def _process_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Process new findings and send notifications."""
        high_severity = [f for f in findings if f.get("severity") == "high"]
        
        if high_severity:
            self._send_notifications(high_severity)
        
        self.findings.extend(findings)
    
    def _send_notifications(self, findings: List[Dict[str, Any]]) -> None:
        """Send notifications for high severity findings."""
        monitoring_config = self.config.get_monitoring_config()
        notifications = monitoring_config.get("notifications", {})
        
        if notifications.get("slack", {}).get("enabled"):
            self._send_slack_notification(findings)
        
        if notifications.get("email", {}).get("enabled"):
            self._send_email_notification(findings)
    
    def _send_slack_notification(self, findings: List[Dict[str, Any]]) -> None:
        """Send notification to Slack."""
        webhook_url = self.config.get("monitoring.notifications.slack.webhook_url")
        if not webhook_url:
            return
        
        message = {
            "text": "🔴 High Severity Security Findings Detected",
            "attachments": [
                {
                    "color": "danger",
                    "title": f"Finding {i+1}: {f.get('title', 'Unknown')}",
                    "text": f.get("description", ""),
                    "fields": [
                        {"title": "Severity", "value": f.get("severity", "unknown"), "short": True},
                        {"title": "Location", "value": f.get("location", "unknown"), "short": True}
                    ]
                }
                for i, f in enumerate(findings)
            ]
        }
        
        try:
            response = requests.post(webhook_url, json=message)
            response.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
    
    def _send_email_notification(self, findings: List[Dict[str, Any]]) -> None:
        """Send notification via email."""
        email_config = self.config.get("monitoring.notifications.email", {})
        if not all(key in email_config for key in ["smtp_server", "smtp_port", "username", "password"]):
            return
        
        # Email sending implementation would go here
        # Using smtplib or similar library
        pass
    
    def _load_config(self, config_path: str) -> None:
        """Load monitoring configuration from file."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                if config:
                    self.config.set("monitoring", config)
        except Exception as e:
            logger.error(f"Failed to load monitoring config: {e}") 