"""
Container image security scanner implementation.
"""
import os
import logging
import subprocess
from typing import Dict, Any, List
import docker
from syft import syft
from grype import grype

class ContainerScanner:
    """Scanner for container image security checks."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.docker_client = docker.from_env()
        self.security_checks = self._load_checks()
        
    def _load_checks(self) -> List[Dict[str, Any]]:
        """Load container security checks."""
        return [
            {
                'id': 'container-001',
                'name': 'Vulnerability Analysis',
                'description': 'Check for known vulnerabilities in container images',
                'severity': 'high'
            },
            {
                'id': 'container-002',
                'name': 'Configuration Security',
                'description': 'Check container configuration for security best practices',
                'severity': 'high'
            },
            {
                'id': 'container-003',
                'name': 'Secret Detection',
                'description': 'Check for exposed secrets in container images',
                'severity': 'high'
            },
            {
                'id': 'container-004',
                'name': 'Package Analysis',
                'description': 'Analyze installed packages and their versions',
                'severity': 'medium'
            }
        ]
        
    def _generate_sbom(self, image_name: str) -> Dict[str, Any]:
        """Generate SBOM for container image."""
        try:
            # Use Syft to generate SBOM
            sbom = syft.scan(image_name)
            return sbom.to_dict()
        except Exception as e:
            self.logger.error(f"Error generating SBOM: {str(e)}")
            return {}
            
    def _check_vulnerabilities(self, image_name: str) -> List[Dict[str, Any]]:
        """Check for vulnerabilities using Grype."""
        findings = []
        try:
            # Use Grype to scan for vulnerabilities
            results = grype.scan(image_name)
            
            for vulnerability in results:
                findings.append({
                    'id': f'container-001-{vulnerability.id}',
                    'name': vulnerability.name,
                    'description': vulnerability.description,
                    'severity': vulnerability.severity.lower(),
                    'package': vulnerability.package,
                    'version': vulnerability.version,
                    'fix_version': vulnerability.fix_version
                })
        except Exception as e:
            self.logger.error(f"Error checking vulnerabilities: {str(e)}")
        return findings
        
    def _check_configuration(self, image_name: str) -> List[Dict[str, Any]]:
        """Check container configuration."""
        findings = []
        try:
            # Get container configuration
            image = self.docker_client.images.get(image_name)
            config = image.attrs['Config']
            
            # Check for root user
            if config.get('User') == 'root':
                findings.append({
                    'id': 'container-002-001',
                    'name': 'Root User',
                    'description': 'Container runs as root user',
                    'severity': 'high'
                })
                
            # Check for exposed ports
            if config.get('ExposedPorts'):
                findings.append({
                    'id': 'container-002-002',
                    'name': 'Exposed Ports',
                    'description': f'Container exposes ports: {list(config["ExposedPorts"].keys())}',
                    'severity': 'medium'
                })
                
            # Check for environment variables
            if config.get('Env'):
                sensitive_vars = ['PASSWORD', 'SECRET', 'KEY', 'TOKEN']
                for env_var in config['Env']:
                    if any(sensitive in env_var.upper() for sensitive in sensitive_vars):
                        findings.append({
                            'id': 'container-002-003',
                            'name': 'Sensitive Environment Variable',
                            'description': f'Container contains sensitive environment variable: {env_var.split("=")[0]}',
                            'severity': 'high'
                        })
        except Exception as e:
            self.logger.error(f"Error checking configuration: {str(e)}")
        return findings
        
    def _check_secrets(self, image_name: str) -> List[Dict[str, Any]]:
        """Check for exposed secrets."""
        findings = []
        try:
            # Use TruffleHog to scan for secrets
            cmd = ['trufflehog', 'filesystem', '--directory=/tmp/container', '--json']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    secret = json.loads(line)
                    findings.append({
                        'id': 'container-003-001',
                        'name': 'Exposed Secret',
                        'description': f'Found {secret["reason"]} in {secret["path"]}',
                        'severity': 'high',
                        'file': secret['path'],
                        'line': secret.get('line')
                    })
        except Exception as e:
            self.logger.error(f"Error checking secrets: {str(e)}")
        return findings
        
    def _check_packages(self, sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze installed packages."""
        findings = []
        try:
            for package in sbom.get('artifacts', []):
                # Check for outdated packages
                if package.get('version') and package.get('latest_version'):
                    if package['version'] != package['latest_version']:
                        findings.append({
                            'id': 'container-004-001',
                            'name': 'Outdated Package',
                            'description': f'Package {package["name"]} is outdated (current: {package["version"]}, latest: {package["latest_version"]})',
                            'severity': 'medium',
                            'package': package['name'],
                            'current_version': package['version'],
                            'latest_version': package['latest_version']
                        })
        except Exception as e:
            self.logger.error(f"Error checking packages: {str(e)}")
        return findings
        
    def scan(self, target: str) -> Dict[str, Any]:
        """Perform container security scan."""
        try:
            # Generate SBOM
            sbom = self._generate_sbom(target)
            
            # Run security checks
            findings = []
            findings.extend(self._check_vulnerabilities(target))
            findings.extend(self._check_configuration(target))
            findings.extend(self._check_secrets(target))
            findings.extend(self._check_packages(sbom))
            
            # Generate summary
            summary = {
                'total_findings': len(findings),
                'high_severity': len([f for f in findings if f['severity'] == 'high']),
                'medium_severity': len([f for f in findings if f['severity'] == 'medium']),
                'low_severity': len([f for f in findings if f['severity'] == 'low'])
            }
            
            return {
                'findings': findings,
                'summary': summary,
                'sbom': sbom
            }
            
        except Exception as e:
            self.logger.error(f"Error performing container security scan: {str(e)}")
            return {
                'error': str(e),
                'findings': [],
                'summary': {
                    'total_findings': 0,
                    'high_severity': 0,
                    'medium_severity': 0,
                    'low_severity': 0
                }
            } 