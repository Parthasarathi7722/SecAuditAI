"""
AI integration module for SecAuditAI.
"""
import os
from typing import Dict, Any, List, Optional
import ollama
from pathlib import Path
import json
import hashlib
import time
import requests
from datetime import datetime, timedelta

class AIManager:
    """Manages AI model interactions and caching."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.cache_dir = os.path.expanduser(config.get('cache_dir', '~/.secauditai/cache'))
        self._ensure_cache_dir()
        self.model_name = config.get('model_name', 'codellama')
        self.max_tokens = config.get('max_tokens', 2048)
        self.temperature = config.get('temperature', 0.7)
        self.vulnerability_types = config.get('vulnerability_types', [])
        self.confidence_threshold = config.get('confidence_threshold', 0.8)
        self.nvd_api_key = os.getenv('NVD_API_KEY')
        self.nvd_cache_dir = os.path.join(self.cache_dir, 'nvd')
        self.custom_patterns = self._load_custom_patterns()
        self.models = self._load_models()
        os.makedirs(self.nvd_cache_dir, exist_ok=True)

    def _ensure_cache_dir(self) -> None:
        """Ensure cache directory exists."""
        os.makedirs(self.cache_dir, exist_ok=True)

    def _get_cache_path(self, prompt: str) -> str:
        """Generate cache file path for a prompt."""
        prompt_hash = hashlib.md5(prompt.encode()).hexdigest()
        return os.path.join(self.cache_dir, f"{prompt_hash}.json")

    def _load_from_cache(self, prompt: str) -> Optional[Dict[str, Any]]:
        """Load response from cache if available."""
        cache_path = self._get_cache_path(prompt)
        if os.path.exists(cache_path):
            with open(cache_path, 'r') as f:
                return json.load(f)
        return None

    def _save_to_cache(self, prompt: str, response: Dict[str, Any]) -> None:
        """Save response to cache."""
        cache_path = self._get_cache_path(prompt)
        with open(cache_path, 'w') as f:
            json.dump(response, f)

    def _fetch_nvd_data(self, cve_id: str) -> Dict[str, Any]:
        """Fetch CVE data from NVD."""
        cache_file = os.path.join(self.nvd_cache_dir, f"{cve_id}.json")
        
        # Check cache first
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                return json.load(f)
        
        # Fetch from NVD API
        headers = {}
        if self.nvd_api_key:
            headers['apiKey'] = self.nvd_api_key
        
        url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            with open(cache_file, 'w') as f:
                json.dump(data, f)
            return data
        return {}

    def _load_custom_patterns(self) -> List[Dict[str, Any]]:
        """Load custom vulnerability patterns."""
        patterns_file = os.path.join(self.cache_dir, 'custom_patterns.json')
        if os.path.exists(patterns_file):
            with open(patterns_file, 'r') as f:
                return json.load(f)
        return []

    def _load_models(self) -> Dict[str, Any]:
        """Load available AI models."""
        return {
            'codellama': {
                'name': 'codellama',
                'description': 'Code Llama for code analysis',
                'supported_tasks': ['code_analysis', 'vulnerability_detection']
            },
            'mistral': {
                'name': 'mistral',
                'description': 'Mistral for general security analysis',
                'supported_tasks': ['security_analysis', 'vulnerability_detection']
            },
            'llama2': {
                'name': 'llama2',
                'description': 'Llama 2 for general analysis',
                'supported_tasks': ['general_analysis']
            }
        }

    def add_custom_pattern(self, pattern: Dict[str, Any]) -> None:
        """Add a custom vulnerability pattern."""
        self.custom_patterns.append(pattern)
        patterns_file = os.path.join(self.cache_dir, 'custom_patterns.json')
        with open(patterns_file, 'w') as f:
            json.dump(self.custom_patterns, f)

    def fine_tune_model(self, dataset_path: str, epochs: int = 3, learning_rate: float = 0.0001) -> Dict[str, Any]:
        """Fine-tune the model on a security dataset."""
        try:
            # Load training data
            with open(dataset_path, 'r') as f:
                training_data = json.load(f)
            
            # Prepare training prompts with custom patterns
            prompts = []
            for item in training_data:
                prompt = f"""Analyze the following code for {item['vulnerability_type']} vulnerabilities:
{item['code']}

Custom patterns to check:
{json.dumps(self.custom_patterns, indent=2)}

Expected findings:
{item['expected_findings']}"""
                prompts.append(prompt)
            
            # Fine-tune the model
            training_results = []
            for epoch in range(epochs):
                for prompt in prompts:
                    response = ollama.generate(
                        model=self.model_name,
                        prompt=prompt,
                        max_tokens=self.max_tokens,
                        temperature=self.temperature,
                        learning_rate=learning_rate
                    )
                    training_results.append({
                        "epoch": epoch,
                        "prompt": prompt,
                        "response": response['response']
                    })
            
            # Save training results
            results_file = os.path.join(self.cache_dir, f"fine_tuning_results_{int(time.time())}.json")
            with open(results_file, 'w') as f:
                json.dump(training_results, f)
            
            return {
                "status": "success",
                "message": "Model fine-tuning completed",
                "results_file": results_file,
                "epochs": epochs,
                "samples": len(prompts)
            }
            
        except Exception as e:
            return {
                "status": "failed",
                "error": str(e)
            }

    def switch_model(self, model_name: str) -> bool:
        """Switch to a different AI model."""
        if model_name in self.models:
            self.model_name = model_name
            return True
        return False

    def analyze_code(self, code: str, language: str) -> Dict[str, Any]:
        """Analyze code for security vulnerabilities."""
        prompt = f"""Analyze the following {language} code for security vulnerabilities:
{code}

Custom patterns to check:
{json.dumps(self.custom_patterns, indent=2)}

Provide a detailed analysis including:
1. Potential security issues
2. Severity level for each issue
3. Recommended fixes
4. Best practices that should be followed"""

        # Check cache first
        cached_response = self._load_from_cache(prompt)
        if cached_response:
            return cached_response

        try:
            response = ollama.generate(
                model=self.model_name,
                prompt=prompt,
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )

            # Parse response and map to known vulnerabilities
            findings = self._parse_ai_response(response['response'])
            
            # Enrich findings with NVD data
            enriched_findings = []
            for finding in findings:
                if 'cve_id' in finding:
                    nvd_data = self._fetch_nvd_data(finding['cve_id'])
                    if nvd_data:
                        finding['nvd_data'] = nvd_data
                enriched_findings.append(finding)

            result = {
                "analysis": response['response'],
                "findings": enriched_findings,
                "model": self.model_name,
                "timestamp": time.time()
            }

            self._save_to_cache(prompt, result)
            return result

        except Exception as e:
            return {
                "error": str(e),
                "status": "failed"
            }

    def _parse_ai_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse AI response into structured findings."""
        findings = []
        lines = response.split('\n')
        
        for line in lines:
            if 'CVE-' in line:
                cve_id = line.split('CVE-')[1].split()[0]
                findings.append({
                    "type": "cve",
                    "cve_id": f"CVE-{cve_id}",
                    "confidence": 0.9
                })
            elif any(vuln_type in line.lower() for vuln_type in self.vulnerability_types):
                findings.append({
                    "type": "vulnerability",
                    "description": line.strip(),
                    "confidence": 0.8
                })
            # Check custom patterns
            for pattern in self.custom_patterns:
                if pattern['pattern'] in line.lower():
                    findings.append({
                        "type": "custom",
                        "pattern_id": pattern['id'],
                        "description": line.strip(),
                        "confidence": pattern.get('confidence', 0.7)
                    })
        
        return findings

    def analyze_infrastructure(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze infrastructure configuration for security issues."""
        prompt = f"""Analyze the following infrastructure configuration for security issues:
{json.dumps(config, indent=2)}

Custom patterns to check:
{json.dumps(self.custom_patterns, indent=2)}

Provide a detailed analysis including:
1. Potential security misconfigurations
2. Severity level for each issue
3. Recommended fixes
4. Best practices that should be followed"""

        # Check cache first
        cached_response = self._load_from_cache(prompt)
        if cached_response:
            return cached_response

        try:
            response = ollama.generate(
                model=self.model_name,
                prompt=prompt,
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )

            result = {
                "analysis": response['response'],
                "model": self.model_name,
                "timestamp": time.time()
            }

            self._save_to_cache(prompt, result)
            return result

        except Exception as e:
            return {
                "error": str(e),
                "status": "failed"
            } 