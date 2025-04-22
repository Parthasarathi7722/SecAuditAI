"""
GCP security scanner implementation.
"""
import os
import logging
from typing import Dict, Any, List
from google.cloud import compute_v1
from google.cloud import storage
from google.cloud import container_v1
from google.cloud import securitycenter_v1
from google.oauth2 import service_account

class GCPScanner:
    """Scanner for GCP security checks."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.credentials = self._get_credentials()
        self.security_checks = self._load_checks()
        
    def _get_credentials(self) -> service_account.Credentials:
        """Get GCP credentials from config or environment."""
        try:
            creds_path = self.config.get('gcp', {}).get('credentials_path')
            if creds_path and os.path.exists(creds_path):
                return service_account.Credentials.from_service_account_file(creds_path)
            return None
        except Exception as e:
            self.logger.error(f"Error loading GCP credentials: {str(e)}")
            return None
            
    def _load_checks(self) -> List[Dict[str, Any]]:
        """Load GCP security checks."""
        return [
            {
                'id': 'gcp-001',
                'name': 'Compute Engine Security',
                'description': 'Check Compute Engine instances for security best practices',
                'severity': 'high'
            },
            {
                'id': 'gcp-002',
                'name': 'Storage Security',
                'description': 'Check Cloud Storage buckets for security configurations',
                'severity': 'high'
            },
            {
                'id': 'gcp-003',
                'name': 'Kubernetes Security',
                'description': 'Check GKE clusters for security configurations',
                'severity': 'high'
            },
            {
                'id': 'gcp-004',
                'name': 'IAM Security',
                'description': 'Check IAM policies and permissions',
                'severity': 'high'
            },
            {
                'id': 'gcp-005',
                'name': 'Network Security',
                'description': 'Check VPC and firewall configurations',
                'severity': 'high'
            }
        ]
        
    def _check_compute_security(self) -> List[Dict[str, Any]]:
        """Check Compute Engine security."""
        findings = []
        try:
            client = compute_v1.InstancesClient(credentials=self.credentials)
            for zone in client.list_zones(project=self.config['gcp']['project_id']):
                for instance in client.list(project=self.config['gcp']['project_id'], zone=zone.name):
                    # Check for public IPs
                    if any(access_config.nat_ip for interface in instance.network_interfaces 
                          for access_config in interface.access_configs):
                        findings.append({
                            'id': 'gcp-001-001',
                            'name': 'Public IP Exposure',
                            'description': f'Instance {instance.name} has a public IP',
                            'severity': 'high',
                            'resource': instance.self_link
                        })
                    
                    # Check for service account usage
                    if not instance.service_accounts:
                        findings.append({
                            'id': 'gcp-001-002',
                            'name': 'No Service Account',
                            'description': f'Instance {instance.name} is not using a service account',
                            'severity': 'medium',
                            'resource': instance.self_link
                        })
        except Exception as e:
            self.logger.error(f"Error checking Compute Engine security: {str(e)}")
        return findings
        
    def _check_storage_security(self) -> List[Dict[str, Any]]:
        """Check Cloud Storage security."""
        findings = []
        try:
            client = storage.Client(credentials=self.credentials)
            for bucket in client.list_buckets():
                # Check for public access
                if bucket.iam_configuration.public_access_prevention != 'enforced':
                    findings.append({
                        'id': 'gcp-002-001',
                        'name': 'Public Bucket Access',
                        'description': f'Bucket {bucket.name} allows public access',
                        'severity': 'high',
                        'resource': bucket.self_link
                    })
                
                # Check for uniform bucket level access
                if not bucket.iam_configuration.uniform_bucket_level_access:
                    findings.append({
                        'id': 'gcp-002-002',
                        'name': 'Non-Uniform Access',
                        'description': f'Bucket {bucket.name} does not use uniform bucket level access',
                        'severity': 'medium',
                        'resource': bucket.self_link
                    })
        except Exception as e:
            self.logger.error(f"Error checking Cloud Storage security: {str(e)}")
        return findings
        
    def _check_kubernetes_security(self) -> List[Dict[str, Any]]:
        """Check GKE security."""
        findings = []
        try:
            client = container_v1.ClusterManagerClient(credentials=self.credentials)
            for cluster in client.list_clusters(project_id=self.config['gcp']['project_id']).clusters:
                # Check for private cluster
                if not cluster.private_cluster_config.enable_private_nodes:
                    findings.append({
                        'id': 'gcp-003-001',
                        'name': 'Non-Private Cluster',
                        'description': f'Cluster {cluster.name} is not private',
                        'severity': 'high',
                        'resource': cluster.self_link
                    })
                
                # Check for workload identity
                if not cluster.workload_identity_config:
                    findings.append({
                        'id': 'gcp-003-002',
                        'name': 'No Workload Identity',
                        'description': f'Cluster {cluster.name} does not use workload identity',
                        'severity': 'medium',
                        'resource': cluster.self_link
                    })
        except Exception as e:
            self.logger.error(f"Error checking GKE security: {str(e)}")
        return findings
        
    def _check_iam_security(self) -> List[Dict[str, Any]]:
        """Check IAM security."""
        findings = []
        try:
            client = securitycenter_v1.SecurityCenterClient(credentials=self.credentials)
            for finding in client.list_findings(
                parent=f"projects/{self.config['gcp']['project_id']}/sources/-"
            ):
                if finding.category == 'IAM_ANOMALY':
                    findings.append({
                        'id': 'gcp-004-001',
                        'name': 'IAM Anomaly',
                        'description': finding.description,
                        'severity': finding.severity.lower(),
                        'resource': finding.resource_name
                    })
        except Exception as e:
            self.logger.error(f"Error checking IAM security: {str(e)}")
        return findings
        
    def _check_network_security(self) -> List[Dict[str, Any]]:
        """Check network security."""
        findings = []
        try:
            client = compute_v1.FirewallsClient(credentials=self.credentials)
            for firewall in client.list(project=self.config['gcp']['project_id']):
                # Check for overly permissive rules
                if any(rule.get('IPProtocol') == 'all' for rule in firewall.allowed):
                    findings.append({
                        'id': 'gcp-005-001',
                        'name': 'Overly Permissive Firewall',
                        'description': f'Firewall rule {firewall.name} allows all protocols',
                        'severity': 'high',
                        'resource': firewall.self_link
                    })
        except Exception as e:
            self.logger.error(f"Error checking network security: {str(e)}")
        return findings
        
    def scan(self, target: str) -> Dict[str, Any]:
        """Perform GCP security scan."""
        if not self.credentials:
            return {
                'error': 'GCP credentials not configured',
                'findings': [],
                'summary': {
                    'total_findings': 0,
                    'high_severity': 0,
                    'medium_severity': 0,
                    'low_severity': 0
                }
            }
            
        try:
            findings = []
            findings.extend(self._check_compute_security())
            findings.extend(self._check_storage_security())
            findings.extend(self._check_kubernetes_security())
            findings.extend(self._check_iam_security())
            findings.extend(self._check_network_security())
            
            # Generate summary
            summary = {
                'total_findings': len(findings),
                'high_severity': len([f for f in findings if f['severity'] == 'high']),
                'medium_severity': len([f for f in findings if f['severity'] == 'medium']),
                'low_severity': len([f for f in findings if f['severity'] == 'low'])
            }
            
            return {
                'findings': findings,
                'summary': summary
            }
            
        except Exception as e:
            self.logger.error(f"Error performing GCP security scan: {str(e)}")
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