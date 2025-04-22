"""
Azure infrastructure security scanner plugin.
"""
import os
from typing import Dict, Any, List
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.compute import ComputeManagementClient
from .. import ScannerPlugin

class AzureScanner(ScannerPlugin):
    """Azure infrastructure security scanner implementation."""
    
    def __init__(self):
        self.checks = self._load_checks()
        self.credential = DefaultAzureCredential()

    def _load_checks(self) -> List[Dict[str, Any]]:
        """Load Azure security checks."""
        return [
            {
                "id": "azure-001",
                "name": "Public Network Access",
                "description": "Check for resources with public network access",
                "severity": "high"
            },
            {
                "id": "azure-002",
                "name": "Storage Account Security",
                "description": "Check storage account security settings",
                "severity": "medium"
            },
            {
                "id": "azure-003",
                "name": "Virtual Machine Security",
                "description": "Check virtual machine security settings",
                "severity": "medium"
            }
        ]

    def _check_public_access(self, resource_client: ResourceManagementClient, 
                           subscription_id: str, resource_group: str) -> List[Dict[str, Any]]:
        """Check for resources with public network access."""
        findings = []
        
        try:
            # Check network security groups
            network_client = NetworkManagementClient(self.credential, subscription_id)
            nsgs = network_client.network_security_groups.list(resource_group)
            
            for nsg in nsgs:
                for rule in nsg.security_rules:
                    if rule.access == "Allow" and rule.direction == "Inbound":
                        if rule.source_address_prefix == "*" or rule.source_address_prefix == "0.0.0.0/0":
                            findings.append({
                                "check_id": "azure-001",
                                "resource": f"NSG: {nsg.name}",
                                "status": "failed",
                                "message": f"Public inbound access allowed in rule: {rule.name}",
                                "severity": "high",
                                "recommendation": "Restrict inbound access to specific IP ranges"
                            })
        except Exception as e:
            findings.append({
                "check_id": "azure-001",
                "resource": "Network Security Groups",
                "status": "error",
                "message": f"Error checking public access: {str(e)}",
                "severity": "high"
            })
        
        return findings

    def _check_storage_security(self, storage_client: StorageManagementClient,
                              subscription_id: str, resource_group: str) -> List[Dict[str, Any]]:
        """Check storage account security settings."""
        findings = []
        
        try:
            storage_accounts = storage_client.storage_accounts.list_by_resource_group(resource_group)
            
            for account in storage_accounts:
                # Check if public access is enabled
                if account.allow_blob_public_access:
                    findings.append({
                        "check_id": "azure-002",
                        "resource": f"Storage Account: {account.name}",
                        "status": "failed",
                        "message": "Public blob access is enabled",
                        "severity": "medium",
                        "recommendation": "Disable public blob access"
                    })
                
                # Check if HTTPS is required
                if not account.enable_https_traffic_only:
                    findings.append({
                        "check_id": "azure-002",
                        "resource": f"Storage Account: {account.name}",
                        "status": "failed",
                        "message": "HTTPS traffic is not enforced",
                        "severity": "medium",
                        "recommendation": "Enable HTTPS traffic only"
                    })
        except Exception as e:
            findings.append({
                "check_id": "azure-002",
                "resource": "Storage Accounts",
                "status": "error",
                "message": f"Error checking storage security: {str(e)}",
                "severity": "medium"
            })
        
        return findings

    def _check_vm_security(self, compute_client: ComputeManagementClient,
                          subscription_id: str, resource_group: str) -> List[Dict[str, Any]]:
        """Check virtual machine security settings."""
        findings = []
        
        try:
            vms = compute_client.virtual_machines.list(resource_group)
            
            for vm in vms:
                # Check if encryption is enabled
                if not vm.storage_profile.os_disk.encryption_settings:
                    findings.append({
                        "check_id": "azure-003",
                        "resource": f"VM: {vm.name}",
                        "status": "failed",
                        "message": "Disk encryption is not enabled",
                        "severity": "medium",
                        "recommendation": "Enable disk encryption"
                    })
                
                # Check if managed identity is enabled
                if not vm.identity:
                    findings.append({
                        "check_id": "azure-003",
                        "resource": f"VM: {vm.name}",
                        "status": "failed",
                        "message": "Managed identity is not enabled",
                        "severity": "medium",
                        "recommendation": "Enable managed identity"
                    })
        except Exception as e:
            findings.append({
                "check_id": "azure-003",
                "resource": "Virtual Machines",
                "status": "error",
                "message": f"Error checking VM security: {str(e)}",
                "severity": "medium"
            })
        
        return findings

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform Azure infrastructure security scan."""
        subscription_id = kwargs.get('subscription')
        resource_group = kwargs.get('resource_group')
        
        if not subscription_id or not resource_group:
            return {
                "scanner": self.get_name(),
                "target": target,
                "findings": [{
                    "check_id": "azure-000",
                    "resource": "Azure Configuration",
                    "status": "error",
                    "message": "Missing subscription ID or resource group"
                }],
                "summary": {
                    "total": 1,
                    "failed": 0,
                    "passed": 0,
                    "error": 1
                }
            }
        
        try:
            # Initialize Azure clients
            resource_client = ResourceManagementClient(self.credential, subscription_id)
            storage_client = StorageManagementClient(self.credential, subscription_id)
            compute_client = ComputeManagementClient(self.credential, subscription_id)
            
            # Run security checks
            findings = []
            findings.extend(self._check_public_access(resource_client, subscription_id, resource_group))
            findings.extend(self._check_storage_security(storage_client, subscription_id, resource_group))
            findings.extend(self._check_vm_security(compute_client, subscription_id, resource_group))
            
            return {
                "scanner": self.get_name(),
                "target": target,
                "findings": findings,
                "summary": {
                    "total": len(findings),
                    "failed": len([f for f in findings if f['status'] == 'failed']),
                    "passed": len([f for f in findings if f['status'] == 'passed']),
                    "error": len([f for f in findings if f['status'] == 'error'])
                }
            }
            
        except Exception as e:
            return {
                "scanner": self.get_name(),
                "target": target,
                "findings": [{
                    "check_id": "azure-000",
                    "resource": "Azure Scan",
                    "status": "error",
                    "message": f"Error during Azure scan: {str(e)}"
                }],
                "summary": {
                    "total": 1,
                    "failed": 0,
                    "passed": 0,
                    "error": 1
                }
            }

    def get_name(self) -> str:
        """Get scanner name."""
        return "azure"

    def get_description(self) -> str:
        """Get scanner description."""
        return "Azure infrastructure security scanner" 