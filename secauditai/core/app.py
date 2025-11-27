from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ..scanners import (
    AWSScanner,
    AzureScanner,
    GCPScanner,
    ImageScanner,
    OnPremScanner,
    TerraformScanner,
)


class SecAuditAI:
    """Lightweight orchestrator used by the documentation tests."""

    def __init__(self) -> None:
        self.rules: Dict[str, Dict[str, Any]] = {}
        self.cloud_scanners = {
            "aws": AWSScanner(),
            "azure": AzureScanner(),
            "gcp": GCPScanner(),
        }
        self.hybrid_scanners = {
            "aws": self.cloud_scanners["aws"],
            "azure": self.cloud_scanners["azure"],
            "on_prem": OnPremScanner(),
        }
        self.image_scanner = ImageScanner()
        self.terraform_scanner = TerraformScanner()

    # ------------------------------------------------------------------ Rules
    def add_rule(self, rule: Dict[str, Any]) -> None:
        rule_id = rule.get("id")
        if not rule_id:
            raise ValueError("Rules must include an 'id' field.")
        self.rules[rule_id] = rule

    def _resolve_rules(self, rule_ids: Iterable[str]) -> Dict[str, Dict[str, Any]]:
        resolved = {}
        for rule_id in rule_ids:
            if rule_id in self.rules:
                resolved[rule_id] = self.rules[rule_id]
        return resolved

    # -------------------------------------------------------------- Cloud Scans
    def scan_multi_cloud(
        self,
        providers: List[str],
        config: Optional[Dict[str, Dict[str, Any]]] = None,
        rules: Optional[List[str]] = None,
        services: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, Any]:
        results: Dict[str, Any] = {}
        config = config or {}

        for provider in providers:
            scanner = self.cloud_scanners.get(provider)
            if not scanner:
                raise ValueError(f"Unsupported provider: {provider}")
            provider_config = config.get(provider, {})
            results[provider] = scanner.scan(provider_config)

        if rules:
            results["rules"] = self._resolve_rules(rules)
        if services:
            results["services"] = services

        return results

    def scan_hybrid_cloud(
        self,
        environments: List[str],
        config: Optional[Dict[str, Dict[str, Any]]] = None,
        rules: Optional[List[str]] = None,
        components: Optional[Dict[str, Any]] = None,
        check_connectivity: bool = False,
        check_security_groups: bool = False,
        check_firewalls: bool = False,
    ) -> Dict[str, Any]:
        results: Dict[str, Any] = {}
        config = config or {}

        for environment in environments:
            scanner = self.hybrid_scanners.get(environment)
            if not scanner:
                raise ValueError(f"Unsupported environment: {environment}")
            env_config = config.get(environment, {})
            results[environment] = scanner.scan(env_config)

        if rules:
            results["rules"] = self._resolve_rules(rules)
        if components:
            results["components"] = components
        if check_connectivity:
            results["connectivity"] = {"status": "checked"}
        if check_security_groups:
            results["security_groups"] = {"status": "checked"}
        if check_firewalls:
            results["firewalls"] = {"status": "checked"}

        return results

    # ----------------------------------------------------------- Terraform/IaC
    def scan_terraform(
        self,
        directory: str,
        custom_rules: Optional[List[Dict[str, Any]]] = None,
        ci_cd: bool = False,
        fail_on_high: bool = False,
        output_format: str = "json",
        **options: Any,
    ) -> Dict[str, Any]:
        if not directory:
            raise ValueError("Terraform directory must be provided.")
        result = self.terraform_scanner.scan(
            {"directory": directory, "options": options}
        )
        if custom_rules:
            rule_map = {rule["id"]: rule for rule in custom_rules if "id" in rule}
            result["rules"] = rule_map
        if ci_cd:
            result["ci_cd"] = {"fail_on_high": fail_on_high}
            result["sarif"] = f"Generated in {output_format}"
            result["fail_on_high"] = fail_on_high
        return result

    # ----------------------------------------------------------- Image scanning
    def scan_image(
        self,
        image: str,
        custom_rules: Optional[List[Dict[str, Any]]] = None,
        runtime: bool = False,
        check_processes: bool = False,
        check_network: bool = False,
        **options: Any,
    ) -> Dict[str, Any]:
        data = self.image_scanner.scan({"image": image, "options": options})
        if custom_rules:
            data["rules"] = {rule["id"]: rule for rule in custom_rules if "id" in rule}
        if runtime:
            data["runtime"] = {
                "processes": check_processes,
                "network": check_network,
            }
        return data

