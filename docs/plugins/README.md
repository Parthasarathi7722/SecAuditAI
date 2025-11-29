# Plugin Development Guide

This guide explains how to develop scanner plugins for SecAuditAI.

## Scanner Plugin Interface

All scanner plugins must implement the `ScannerPlugin` interface:

```python
from secauditai.plugins import ScannerPlugin

class CustomScanner(ScannerPlugin):
    def __init__(self):
        self.checks = self._load_checks()
    
    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform security scan and return findings with evidence."""
        findings = []
        # ... scanning logic ...
        # Each finding should include evidence
        findings.append({
            "check_id": "custom-001",
            "resource": "resource_identifier",
            "status": "failed",
            "message": "Description of the issue",
            "severity": "high",
            "recommendation": "How to fix the issue",
            "evidence": {
                # Detailed evidence supporting the finding
            }
        })
        return {
            "scanner": self.get_name(),
            "target": target,
            "findings": findings,
            "summary": self._summarize_findings(findings)
        }
    
    def get_name(self) -> str:
        """Return scanner name."""
        return "custom"
    
    def get_description(self) -> str:
        """Return scanner description."""
        return "Custom security scanner"
```

### 2. Analyzer Plugins

```python
from secauditai.plugins.base import BaseAnalyzer

class CustomAnalyzer(BaseAnalyzer):
    def __init__(self, config):
        super().__init__(config)
        self.name = "custom_analyzer"
        self.version = "1.0.0"
    
    def analyze(self, findings, **kwargs):
        # Implement analysis logic
        analysis = {}
        # ... analysis logic ...
        return analysis
```

### 3. Reporter Plugins

```python
from secauditai.plugins.base import BaseReporter

class CustomReporter(BaseReporter):
    def __init__(self, config):
        super().__init__(config)
        self.name = "custom_reporter"
        self.version = "1.0.0"
    
    def report(self, findings, **kwargs):
        # Implement reporting logic
        report = {}
        # ... reporting logic ...
        return report
```

## Plugin Development

### 1. Project Structure

```
custom_plugin/
├── __init__.py
├── scanner.py
├── analyzer.py
├── reporter.py
├── config.py
└── tests/
    ├── __init__.py
    ├── test_scanner.py
    ├── test_analyzer.py
    └── test_reporter.py
```

### 2. Plugin Configuration

```python
# config.py
PLUGIN_CONFIG = {
    "name": "custom_plugin",
    "version": "1.0.0",
    "description": "Custom security plugin",
    "author": "Your Name",
    "license": "MIT",
    "requirements": [
        "dependency1>=1.0.0",
        "dependency2>=2.0.0"
    ],
    "settings": {
        "setting1": {
            "type": "string",
            "default": "value1",
            "description": "Setting 1 description"
        },
        "setting2": {
            "type": "integer",
            "default": 100,
            "description": "Setting 2 description"
        }
    }
}
```

### 3. Plugin Registration

```python
# __init__.py
from secauditai.plugins import PluginRegistry
from .scanner import CustomScanner
from .analyzer import CustomAnalyzer
from .reporter import CustomReporter

def register_plugins():
    PluginRegistry.register_scanner("custom", CustomScanner)
    PluginRegistry.register_analyzer("custom", CustomAnalyzer)
    PluginRegistry.register_reporter("custom", CustomReporter)
```

## Plugin Usage

### 1. Load Plugin

```python
from secauditai import SecAuditAI

# Initialize scanner with plugin
scanner = SecAuditAI()
scanner.load_plugin("custom_plugin")

# Use plugin
results = scanner.scan(
    target="path/to/target",
    plugins=["custom"]
)
```

### 2. Configure Plugin

```python
# Configure plugin
scanner.configure_plugin(
    name="custom",
    settings={
        "setting1": "new_value",
        "setting2": 200
    }
)
```

### 3. Plugin Events

```python
# Subscribe to plugin events
def on_scan_start(event):
    print(f"Scan started: {event}")

def on_scan_complete(event):
    print(f"Scan completed: {event}")

scanner.subscribe("scan_start", on_scan_start)
scanner.subscribe("scan_complete", on_scan_complete)
```

## Best Practices

1. **Code Quality**
   - Follow PEP 8 style guide
   - Write comprehensive tests
   - Document code thoroughly

2. **Error Handling**
   - Use appropriate exceptions
   - Provide meaningful error messages
   - Log errors properly

3. **Performance**
   - Optimize resource usage
   - Use appropriate data structures
   - Implement caching where needed

4. **Security**
   - Validate all inputs
   - Handle sensitive data properly
   - Follow security best practices

## Testing

### 1. Unit Tests

```python
# tests/test_scanner.py
import unittest
from custom_plugin.scanner import CustomScanner

class TestCustomScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = CustomScanner({})
    
    def test_scan(self):
        results = self.scanner.scan("test_target")
        self.assertIsInstance(results, list)
```

### 2. Integration Tests

```python
# tests/test_integration.py
import unittest
from secauditai import SecAuditAI

class TestPluginIntegration(unittest.TestCase):
    def setUp(self):
        self.scanner = SecAuditAI()
        self.scanner.load_plugin("custom_plugin")
    
    def test_plugin_scan(self):
        results = self.scanner.scan(
            target="test_target",
            plugins=["custom"]
        )
        self.assertIsInstance(results, dict)
```

## Distribution

### 1. Package Plugin

```bash
# Create distribution package
python setup.py sdist bdist_wheel

# Upload to PyPI
twine upload dist/*
```

### 2. Install Plugin

```bash
# Install from PyPI
pip install custom-plugin

# Install from source
pip install -e .
```

## Troubleshooting

1. **Plugin Loading Issues**
   - Check plugin structure
   - Verify dependencies
   - Check configuration

2. **Performance Issues**
   - Profile plugin code
   - Optimize algorithms
   - Check resource usage

3. **Integration Issues**
   - Verify API compatibility
   - Check event handling
   - Test with different configurations 