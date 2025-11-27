#!/usr/bin/env python3
"""
Slack Notifications
-----------------
This module provides Slack notification capabilities for security alerts.
"""

import json
import requests
from typing import Dict, List, Optional
from datetime import datetime

class SlackNotifier:
    def __init__(self, webhook_url: str, channel: Optional[str] = None):
        self.webhook_url = webhook_url
        self.channel = channel
        self.session = requests.Session()
    
    def send_alert(self, 
                  title: str, 
                  message: str, 
                  severity: str,
                  details: Optional[Dict] = None,
                  timestamp: Optional[datetime] = None) -> bool:
        """
        Send a security alert to Slack
        
        Args:
            title: Alert title
            message: Alert message
            severity: Alert severity (high, medium, low)
            details: Optional additional details
            timestamp: Optional timestamp (defaults to now)
            
        Returns:
            bool indicating success
        """
        if not timestamp:
            timestamp = datetime.now()
        
        # Map severity to color
        severity_colors = {
            "high": "#FF0000",    # Red
            "medium": "#FFA500",  # Orange
            "low": "#FFFF00"      # Yellow
        }
        
        # Create blocks for the message
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": title,
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": message
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:* {severity.upper()}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Time:* {timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
                    }
                ]
            }
        ]
        
        # Add details if provided
        if details:
            details_text = "```\n" + json.dumps(details, indent=2) + "\n```"
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Details:*\n{details_text}"
                }
            })
        
        # Create the payload
        payload = {
            "blocks": blocks,
            "attachments": [
                {
                    "color": severity_colors.get(severity.lower(), "#808080"),
                    "blocks": blocks
                }
            ]
        }
        
        try:
            response = self.session.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Error sending Slack notification: {str(e)}")
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
                timestamp=alert.get("timestamp")
            )
            results[alert.get("title", "Unknown Alert")] = success
        return results
    
    def send_scan_results(self, 
                         scan_type: str,
                         results: Dict,
                         timestamp: Optional[datetime] = None) -> bool:
        """
        Send formatted scan results to Slack
        
        Args:
            scan_type: Type of scan (e.g., "API", "Container", "IaC")
            results: Scan results dictionary
            timestamp: Optional timestamp
            
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
        summary = "\n".join([
            f"• {count} {severity} severity issues"
            for severity, count in severity_counts.items()
        ])
        
        return self.send_alert(
            title=title,
            message=f"{message}\n\n{summary}",
            severity="high" if severity_counts.get("high", 0) > 0 else "medium",
            details=results,
            timestamp=timestamp
        ) 