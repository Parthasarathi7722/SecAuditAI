"""
Real-time monitoring module for SecAuditAI.
"""
import os
import time
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime
import schedule
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from .plugins import PluginManager
from .config import ConfigManager
from .reports import ReportGenerator

class Monitor:
    """Handles real-time monitoring of security aspects."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.plugin_manager = PluginManager(config)
        self.report_generator = ReportGenerator(config)
        self.console = Console()
        self.monitoring_config = config.get('monitoring', {})
        self.interval = self.monitoring_config.get('interval', 300)  # Default 5 minutes
        self.alert_threshold = self.monitoring_config.get('alert_threshold', 'high')
        self.notifications = self.monitoring_config.get('notifications', {})
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        logs_dir = Path.home() / '.secauditai' / 'logs'
        logs_dir.mkdir(parents=True, exist_ok=True)
        
        # Add file handler
        log_file = logs_dir / f'monitor_{datetime.now().strftime("%Y%m%d")}.log'
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(file_handler)

    def start_monitoring(self, target: str) -> None:
        """Start monitoring the specified target."""
        self.logger.info(f"Starting monitoring for target: {target}")
        self.console.print(Panel(f"Starting monitoring for: {target}", title="SecAuditAI Monitor"))
        
        # Schedule the monitoring job
        schedule.every(self.interval).seconds.do(self._run_scan, target)
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
            self.console.print(Panel("Monitoring stopped", title="SecAuditAI Monitor"))

    def _run_scan(self, target: str) -> None:
        """Run a security scan and handle the results."""
        self.logger.info(f"Running scheduled scan for target: {target}")
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning...", total=100)
            
            # Run all available scanners
            results = {}
            for scanner in self.plugin_manager.get_scanners():
                scanner_name = scanner.__class__.__name__
                progress.update(task, description=f"[cyan]Running {scanner_name}...")
                
                try:
                    scan_results = scanner.scan(target)
                    results[scanner_name] = scan_results
                    
                    # Check for high severity findings
                    if self._has_high_severity_findings(scan_results):
                        self._send_alert(scanner_name, scan_results)
                    
                    progress.update(task, advance=100/len(self.plugin_manager.get_scanners()))
                except Exception as e:
                    self.logger.error(f"Error running {scanner_name}: {str(e)}")
                    progress.update(task, advance=100/len(self.plugin_manager.get_scanners()))
        
        # Generate report
        report_id = self.report_generator.generate_report(results)
        self.logger.info(f"Generated report: {report_id}")

    def _has_high_severity_findings(self, results: Dict[str, Any]) -> bool:
        """Check if there are any high severity findings."""
        if 'findings' not in results:
            return False
            
        for finding in results['findings']:
            if finding.get('severity', '').lower() == 'high':
                return True
        return False

    def _send_alert(self, scanner: str, results: Dict[str, Any]) -> None:
        """Send alert for high severity findings."""
        alert_message = f"High severity findings detected by {scanner}:\n"
        
        for finding in results.get('findings', []):
            if finding.get('severity', '').lower() == 'high':
                alert_message += f"- {finding.get('description', 'Unknown issue')}\n"
        
        self.logger.warning(alert_message)
        
        # Send email alert if configured
        if 'email' in self.notifications:
            self._send_email_alert(alert_message)
        
        # Send Slack alert if configured
        if 'slack_webhook' in self.notifications:
            self._send_slack_alert(alert_message)

    def _send_email_alert(self, message: str) -> None:
        """Send email alert."""
        # TODO: Implement email sending
        self.logger.info("Email alert would be sent here")

    def _send_slack_alert(self, message: str) -> None:
        """Send Slack alert."""
        # TODO: Implement Slack webhook
        self.logger.info("Slack alert would be sent here") 