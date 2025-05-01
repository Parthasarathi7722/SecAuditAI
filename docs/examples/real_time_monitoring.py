#!/usr/bin/env python3
"""
Real-time Monitoring Example
--------------------------
This example demonstrates how to use SecAuditAI's real-time monitoring
capabilities. Note: This is an experimental feature and should be used
with caution in production environments.
"""

from secauditai import RealTimeMonitor
from secauditai.notifications import SlackNotifier, WebhookNotifier

def main():
    # Initialize real-time monitor
    monitor = RealTimeMonitor()
    
    # Enable experimental features
    monitor.enable_experimental()
    
    # Configure notifications
    slack_notifier = SlackNotifier(
        webhook_url="your-slack-webhook-url",
        channel="#security-alerts"
    )
    
    webhook_notifier = WebhookNotifier(
        url="your-webhook-url",
        secret="your-webhook-secret"
    )
    
    # Add notifiers
    monitor.add_notifier(slack_notifier)
    monitor.add_notifier(webhook_notifier)
    
    # Configure monitoring
    monitor.configure(
        check_interval=60,  # 1 minute
        alert_threshold=0.8,  # 80% confidence
        max_alerts_per_hour=10
    )
    
    # Start monitoring
    print("Starting real-time monitoring...")
    try:
        monitor.start(
            targets=[
                {"type": "cloud", "provider": "aws", "region": "us-east-1"},
                {"type": "container", "id": "container-id"},
                {"type": "network", "interface": "eth0"}
            ],
            duration=3600  # 1 hour
        )
    except KeyboardInterrupt:
        print("\nStopping monitoring...")
        monitor.stop()
    
    # Generate monitoring report
    report = monitor.generate_report(
        format="html",
        include_metrics=True,
        include_alerts=True
    )
    
    # Save report
    with open("monitoring_report.html", "w") as f:
        f.write(report)
    
    print("\nMonitoring report generated: monitoring_report.html")

if __name__ == "__main__":
    main() 