"""
Email notification system implementation.
"""
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List
from jinja2 import Template
import os

class EmailNotifier:
    """Handles email notifications for security findings."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.email_config = config.get('notifications', {}).get('email', {})
        self.template = self._load_template()
        
    def _load_template(self) -> Template:
        """Load email template."""
        template_path = os.path.join(
            os.path.dirname(__file__),
            'templates',
            'email_template.html'
        )
        with open(template_path, 'r') as f:
            return Template(f.read())
            
    def _format_findings(self, findings: List[Dict[str, Any]]) -> str:
        """Format findings for email."""
        return self.template.render(
            findings=findings,
            total_findings=len(findings),
            high_severity=len([f for f in findings if f['severity'] == 'high']),
            medium_severity=len([f for f in findings if f['severity'] == 'medium']),
            low_severity=len([f for f in findings if f['severity'] == 'low'])
        )
        
    def _send_email(self, subject: str, body: str) -> bool:
        """Send email notification."""
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.email_config['sender']
            msg['To'] = self.email_config['recipient']
            
            # Add HTML body
            msg.attach(MIMEText(body, 'html'))
            
            # Connect to SMTP server
            with smtplib.SMTP(
                self.email_config['smtp_server'],
                self.email_config['smtp_port']
            ) as server:
                if self.email_config.get('use_tls'):
                    server.starttls()
                    
                # Login if credentials provided
                if self.email_config.get('username') and self.email_config.get('password'):
                    server.login(
                        self.email_config['username'],
                        self.email_config['password']
                    )
                    
                # Send email
                server.send_message(msg)
                
            self.logger.info("Email notification sent successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending email notification: {str(e)}")
            return False
            
    def send_alert(self, findings: List[Dict[str, Any]], scan_type: str) -> bool:
        """Send alert for security findings."""
        if not self.email_config:
            self.logger.warning("Email configuration not found")
            return False
            
        try:
            # Format subject
            subject = f"SecAuditAI Alert: {scan_type} Scan Findings"
            
            # Format body
            body = self._format_findings(findings)
            
            # Send email
            return self._send_email(subject, body)
            
        except Exception as e:
            self.logger.error(f"Error sending alert: {str(e)}")
            return False 