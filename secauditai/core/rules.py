#!/usr/bin/env python3
"""
Custom Rule Engine
----------------
This module provides a flexible rule engine for security scanning.
It allows users to define custom security rules and policies.
"""

from typing import Dict, List, Any, Callable, Optional
import json
import yaml
from pathlib import Path

class RuleEngine:
    def __init__(self):
        self.rules: Dict[str, List[Dict]] = {}
        self.load_default_rules()
    
    def load_default_rules(self):
        """Load default security rules"""
        default_rules = {
            "api": [
                {
                    "name": "insecure_headers",
                    "description": "Check for missing or insecure security headers",
                    "severity": "high",
                    "condition": lambda results: any(
                        not header.get("present") or not header.get("secure")
                        for header in results["headers"].values()
                    )
                },
                {
                    "name": "rate_limit_missing",
                    "description": "Check for missing rate limiting",
                    "severity": "medium",
                    "condition": lambda results: any(
                        not limit.get("blocked")
                        for limit in results["rate_limiting"].values()
                    )
                }
            ],
            "container": [
                {
                    "name": "root_container",
                    "description": "Check for containers running as root",
                    "severity": "high",
                    "condition": lambda results: results.get("user") == "root"
                }
            ],
            "iac": [
                {
                    "name": "insecure_storage",
                    "description": "Check for insecure storage configurations",
                    "severity": "high",
                    "condition": lambda results: any(
                        storage.get("encrypted") == False
                        for storage in results.get("storage", [])
                    )
                }
            ]
        }
        self.rules.update(default_rules)
    
    def load_rules_from_file(self, file_path: str):
        """Load rules from a JSON or YAML file"""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Rules file not found: {file_path}")
        
        with open(file_path, 'r') as f:
            if path.suffix == '.json':
                rules = json.load(f)
            elif path.suffix in ['.yaml', '.yml']:
                rules = yaml.safe_load(f)
            else:
                raise ValueError(f"Unsupported file format: {path.suffix}")
        
        self.rules.update(rules)
    
    def add_rule(self, category: str, rule: Dict):
        """Add a single rule to a category"""
        if category not in self.rules:
            self.rules[category] = []
        self.rules[category].append(rule)
    
    def remove_rule(self, category: str, rule_name: str):
        """Remove a rule from a category"""
        if category in self.rules:
            self.rules[category] = [
                rule for rule in self.rules[category]
                if rule["name"] != rule_name
            ]
    
    def apply_rules(self, category: str, results: Dict) -> List[Dict]:
        """Apply rules for a specific category to scan results"""
        if category not in self.rules:
            return []
        
        violations = []
        for rule in self.rules[category]:
            try:
                if rule["condition"](results):
                    violations.append({
                        "name": rule["name"],
                        "description": rule["description"],
                        "severity": rule["severity"]
                    })
            except Exception as e:
                print(f"Error applying rule {rule['name']}: {str(e)}")
        
        return violations
    
    def validate_rule(self, rule: Dict) -> bool:
        """Validate a rule dictionary"""
        required_fields = ["name", "description", "severity", "condition"]
        return all(field in rule for field in required_fields)
    
    def export_rules(self, file_path: str, format: str = "json"):
        """Export rules to a file"""
        if format not in ["json", "yaml"]:
            raise ValueError("Format must be 'json' or 'yaml'")
        
        with open(file_path, 'w') as f:
            if format == "json":
                json.dump(self.rules, f, indent=2)
            else:
                yaml.dump(self.rules, f, default_flow_style=False)
    
    def get_categories(self) -> List[str]:
        """Get list of rule categories"""
        return list(self.rules.keys())
    
    def get_rules_for_category(self, category: str) -> List[Dict]:
        """Get all rules for a specific category"""
        return self.rules.get(category, [])
    
    def clear_rules(self, category: Optional[str] = None):
        """Clear all rules or rules for a specific category"""
        if category:
            self.rules[category] = []
        else:
            self.rules.clear()
            self.load_default_rules() 