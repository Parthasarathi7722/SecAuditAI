#!/usr/bin/env python3
"""
Webhook Notifications
-------------------
This module provides webhook notification capabilities for security alerts.
"""

import json
import requests
from typing import Dict, List, Optional, Union
from datetime import datetime

class WebhookNotifier:
    def __init__(
        self,
        webhook_url: str | None = None,
        headers: Optional[Dict] = None,
        url: Optional[str] = None,
        secret: Optional[str] = None,
    ):
        self.webhook_url = webhook_url or url or ""
        self.session = requests.Session()
        self.headers = headers or {"Content-Type": "application/json"}
        self.secret = secret
    
    def send_alert(self,
                  title: str,
                  message: str,
                  severity: str,
                  details: Optional[Dict] = None,
                  timestamp: Optional[datetime] = None,
                  custom_fields: Optional[Dict] = None) -> bool:
        """
        Send a security alert via webhook
        
        Args:
            title: Alert title
            message: Alert message
            severity: Alert severity (high, medium, low)
            details: Optional additional details
            timestamp: Optional timestamp (defaults to now)
            custom_fields: Optional custom fields to include
            
        Returns:
            bool indicating success
        """
        if not timestamp:
            timestamp = datetime.now()
        
        # Create the payload
        payload = {
            "title": title,
            "message": message,
            "severity": severity,
            "timestamp": timestamp.isoformat(),
            "details": details or {},
            "custom_fields": custom_fields or {}
        }
        
        try:
            response = self.session.post(
                self.webhook_url,
                json=payload,
                headers=self.headers
            )
            return response.status_code in [200, 201, 202]
        except Exception as e:
            print(f"Error sending webhook notification: {str(e)}")
            return False
    
    def send_batch_alerts(self, alerts: List[Dict]) -> Dict[str, bool]:
        """
        Send multiple alerts in a batch
        
        Args:
            alerts: List of alert dictionaries with required fields
            
        Returns:
            Dict mapping alert titles to success status
        """
        results = {}
        for alert in alerts:
            success = self.send_alert(
                title=alert.get("title", "Security Alert"),
                message=alert.get("message", ""),
                severity=alert.get("severity", "medium"),
                details=alert.get("details"),
                timestamp=alert.get("timestamp"),
                custom_fields=alert.get("custom_fields")
            )
            results[alert.get("title", "Unknown Alert")] = success
        return results
    
    def send_scan_results(self,
                         scan_type: str,
                         results: Dict,
                         timestamp: Optional[datetime] = None,
                         custom_fields: Optional[Dict] = None) -> bool:
        """
        Send formatted scan results via webhook
        
        Args:
            scan_type: Type of scan (e.g., "API", "Container", "IaC")
            results: Scan results dictionary
            timestamp: Optional timestamp
            custom_fields: Optional custom fields
            
        Returns:
            bool indicating success
        """
        if not timestamp:
            timestamp = datetime.now()
        
        # Format the results
        title = f"{scan_type} Security Scan Results"
        message = f"Security scan completed for {scan_type}"
        
        # Count vulnerabilities by severity
        severity_counts = {}
        for result in results.get("vulnerabilities", []):
            severity = result.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Create summary
        summary = {
            "total_issues": sum(severity_counts.values()),
            "by_severity": severity_counts
        }
        
        # Prepare custom fields
        if not custom_fields:
            custom_fields = {}
        custom_fields.update({
            "scan_type": scan_type,
            "summary": summary
        })
        
        return self.send_alert(
            title=title,
            message=message,
            severity="high" if severity_counts.get("high", 0) > 0 else "medium",
            details=results,
            timestamp=timestamp,
            custom_fields=custom_fields
        )
    
    def set_headers(self, headers: Dict):
        """Update webhook headers"""
        self.headers.update(headers)
    
    def add_header(self, key: str, value: str):
        """Add a single header"""
        self.headers[key] = value
    
    def remove_header(self, key: str):
        """Remove a header"""
        if key in self.headers:
            del self.headers[key]
    
    def validate_webhook(self) -> bool:
        """Validate webhook URL and configuration"""
        try:
            response = self.session.get(self.webhook_url)
            return response.status_code in [200, 201, 202]
        except Exception:
            return False 