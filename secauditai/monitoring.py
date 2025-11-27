from __future__ import annotations

import datetime as dt
from collections import Counter
from typing import Any, Dict, List


class SecurityMonitor:
    """Utility class used in tests to model security monitoring workflows."""

    def __init__(self) -> None:
        self.alert_handlers: Dict[str, Any] = {}
        self.scan_history: List[Dict[str, Any]] = []

    def analyze_findings(self, results: Dict[str, Any]) -> Dict[str, Any]:
        findings = results.get("findings", [])
        severity_counts = Counter(f.get("severity", "unknown").lower() for f in findings)
        analysis = {
            "total_findings": len(findings),
            "severity_distribution": severity_counts,
            "trends": {"timestamp": dt.datetime.utcnow().isoformat()},
        }
        return analysis

    def generate_metrics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        findings = results.get("findings", [])
        severity_counts = Counter(f.get("severity", "unknown").lower() for f in findings)
        metrics = {
            "vulnerability_metrics": severity_counts,
            "compliance_metrics": {"checks": len(findings), "passed": 0},
            "risk_metrics": {"score": self._calculate_risk(findings)},
        }
        return metrics

    def send_alerts(self, results: Dict[str, Any]) -> None:
        for finding in results.get("findings", []):
            if finding.get("severity", "").lower() == "high":
                alert = self._format_alert(finding)
                self._dispatch_alert(alert)

    def _dispatch_alert(self, alert: str) -> None:
        for handler in self.alert_handlers.values():
            handler(alert)

    def _format_alert(self, finding: Dict[str, Any]) -> str:
        severity = finding.get("severity", "unknown").upper()
        title = finding.get("title", "Unknown Issue")
        description = finding.get("description", "")
        remediation = finding.get("remediation", "Review and mitigate.")
        formatted = (
            f"[{severity}] {title}\n"
            f"Description: {description}\n"
            f"Remediation: {remediation}\n"
            f"Severity: {severity}\n"
            f"Type: {finding.get('type', 'vulnerability')}\n"
        )
        return formatted

    def _send_slack_alert(self, alert: str) -> bool:
        # Placeholder for Slack integration.
        return bool(alert)

    def _send_email_alert(self, alert: str) -> bool:
        # Placeholder for email integration.
        return bool(alert)

    def track_scan_history(self, results: Dict[str, Any]) -> None:
        entry = {
            "timestamp": dt.datetime.utcnow().isoformat(),
            "results": results,
        }
        self.scan_history.append(entry)

    def get_scan_history(self) -> List[Dict[str, Any]]:
        return list(self.scan_history)

    def _calculate_risk(self, findings: List[Dict[str, Any]]) -> float:
        weights = {"high": 3, "medium": 2, "low": 1}
        if not findings:
            return 0.0
        total = sum(weights.get(f.get("severity", "").lower(), 0) for f in findings)
        normalized = min(total / (3 * len(findings)), 1.0)
        return round(normalized * 100, 2)

