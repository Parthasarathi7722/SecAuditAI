from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional


class RealTimeMonitor:
    """Experimental real-time monitor used for documentation/tests."""

    def __init__(self) -> None:
        self._experimental = False
        self._check_interval = 60
        self._alert_threshold = 0.8
        self._max_alerts_per_hour = 10
        self._notifiers: List[Any] = []
        self._metrics: Dict[str, Any] = {}
        self._alerts: List[Dict[str, Any]] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def enable_experimental(self) -> None:
        self._experimental = True

    def disable_experimental(self) -> None:
        self._experimental = False

    def is_experimental_enabled(self) -> bool:
        return self._experimental

    def add_notifier(self, notifier: Any) -> None:
        self._notifiers.append(notifier)

    def get_notifiers(self) -> List[Any]:
        return list(self._notifiers)

    def configure(
        self,
        check_interval: Optional[int] = None,
        alert_threshold: Optional[float] = None,
        max_alerts_per_hour: Optional[int] = None,
    ) -> None:
        if check_interval is not None:
            if check_interval <= 0:
                raise ValueError("check_interval must be positive")
            self._check_interval = check_interval
        if alert_threshold is not None:
            if not 0 < alert_threshold <= 1:
                raise ValueError("alert_threshold must be between 0 and 1")
            self._alert_threshold = alert_threshold
        if max_alerts_per_hour is not None:
            if max_alerts_per_hour <= 0:
                raise ValueError("max_alerts_per_hour must be positive")
            self._max_alerts_per_hour = max_alerts_per_hour

    def get_check_interval(self) -> int:
        return self._check_interval

    def get_alert_threshold(self) -> float:
        return self._alert_threshold

    def get_max_alerts_per_hour(self) -> int:
        return self._max_alerts_per_hour

    def start(self, targets: List[Dict[str, Any]], duration: int = 60) -> None:
        if not targets:
            raise ValueError("At least one target must be provided")
        valid_types = {"cloud", "container", "network"}
        for target in targets:
            if "type" not in target:
                raise ValueError("Each target must include a 'type' field")
            if target["type"] not in valid_types:
                raise ValueError(f"Unsupported monitoring target: {target['type']}")

        if self._running:
            return

        self._running = True
        end_time = time.time() + duration
        self._thread = threading.Thread(
            target=self._monitor_loop,
            args=(targets, end_time),
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def _monitor_loop(self, targets: List[Dict[str, Any]], end_time: float) -> None:
        while self._running and time.time() < end_time:
            self._record_metrics(targets)
            time.sleep(min(self._check_interval, 1))

    def _record_metrics(self, targets: List[Dict[str, Any]]) -> None:
        for target in targets:
            target_type = target["type"]
            bucket = self._metrics.setdefault(target_type, {"checks": 0})
            bucket["checks"] += 1

    def _simulate_event(self, severity: str = "medium") -> None:
        alert = {
            "severity": severity,
            "timestamp": time.time(),
        }
        self._alerts.append(alert)

    def get_alerts(self) -> List[Dict[str, Any]]:
        return list(self._alerts)

    def get_metrics(self) -> Dict[str, Any]:
        return dict(self._metrics)

    def generate_report(
        self,
        format: str = "html",
        include_metrics: bool = False,
        include_alerts: bool = False,
    ) -> str:
        if format != "html":
            raise ValueError("Only HTML reports are supported in tests")
        metrics_section = ""
        alerts_section = ""
        if include_metrics:
            metrics_section = f"<pre>{self._metrics}</pre>"
        if include_alerts:
            alerts_section = f"<pre>{self._alerts}</pre>"
        return f"<html><body>{metrics_section}{alerts_section}</body></html>"

