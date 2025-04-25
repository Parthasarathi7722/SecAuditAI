import requests
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime
from .config import Config

logger = logging.getLogger(__name__)

class APIClient:
    """API client for SecAuditAI integration."""
    
    def __init__(self):
        self.config = Config()
        self.api_config = self.config.get_api_config()
        self.base_url = f"http://{self.api_config['host']}:{self.api_config['port']}"
        self.headers = {
            "Authorization": f"Bearer {self.api_config['auth_token']}",
            "Content-Type": "application/json"
        }
    
    def scan_code(self, path: str, **kwargs) -> Dict[str, Any]:
        """Scan code repository."""
        try:
            response = requests.post(
                f"{self.base_url}/scan/code",
                json={"path": path, **kwargs},
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to scan code: {e}")
            return {"error": str(e)}
    
    def scan_cloud(self, provider: str, **kwargs) -> Dict[str, Any]:
        """Scan cloud infrastructure."""
        try:
            response = requests.post(
                f"{self.base_url}/scan/cloud/{provider}",
                json=kwargs,
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to scan cloud: {e}")
            return {"error": str(e)}
    
    def generate_report(self, scan_id: str, format: str = "html") -> Dict[str, Any]:
        """Generate report for scan results."""
        try:
            response = requests.get(
                f"{self.base_url}/report/{scan_id}",
                params={"format": format},
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            return {"error": str(e)}
    
    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get status of a scan."""
        try:
            response = requests.get(
                f"{self.base_url}/scan/{scan_id}/status",
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get scan status: {e}")
            return {"error": str(e)}
    
    def list_scans(self, limit: int = 10, offset: int = 0) -> Dict[str, Any]:
        """List recent scans."""
        try:
            response = requests.get(
                f"{self.base_url}/scans",
                params={"limit": limit, "offset": offset},
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to list scans: {e}")
            return {"error": str(e)}
    
    def configure_webhook(self, url: str, events: List[str]) -> Dict[str, Any]:
        """Configure webhook for notifications."""
        try:
            response = requests.post(
                f"{self.base_url}/webhooks",
                json={"url": url, "events": events},
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to configure webhook: {e}")
            return {"error": str(e)}
    
    def get_metrics(self, time_range: str = "24h") -> Dict[str, Any]:
        """Get system metrics."""
        try:
            response = requests.get(
                f"{self.base_url}/metrics",
                params={"time_range": time_range},
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get metrics: {e}")
            return {"error": str(e)}
    
    def export_data(self, scan_id: str, format: str = "json") -> Dict[str, Any]:
        """Export scan data."""
        try:
            response = requests.get(
                f"{self.base_url}/export/{scan_id}",
                params={"format": format},
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to export data: {e}")
            return {"error": str(e)} 