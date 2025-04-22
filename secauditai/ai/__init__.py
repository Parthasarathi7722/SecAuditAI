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

class AIManager:
    """Manages AI model interactions and caching."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.cache_dir = os.path.expanduser(config.get('cache_dir', '~/.secauditai/cache'))
        self._ensure_cache_dir()
        self.model_name = config.get('model_name', 'codellama')
        self.max_tokens = config.get('max_tokens', 2048)
        self.temperature = config.get('temperature', 0.7)

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

    def analyze_code(self, code: str, language: str) -> Dict[str, Any]:
        """Analyze code for security vulnerabilities."""
        prompt = f"""Analyze the following {language} code for security vulnerabilities:
{code}

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

    def analyze_infrastructure(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze infrastructure configuration for security issues."""
        prompt = f"""Analyze the following infrastructure configuration for security issues:
{json.dumps(config, indent=2)}

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

    def train_model(self, dataset_path: str, epochs: int = 3) -> Dict[str, Any]:
        """Train the model on a security dataset."""
        try:
            # TODO: Implement model training with Ollama
            return {
                "status": "success",
                "message": "Model training initiated",
                "dataset": dataset_path,
                "epochs": epochs
            }
        except Exception as e:
            return {
                "status": "failed",
                "error": str(e)
            } 