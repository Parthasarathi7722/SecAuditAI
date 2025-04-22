"""
AWS security scanner plugin.
"""
import boto3
from typing import Dict, Any, List
from .. import ScannerPlugin

class AWSScanner(ScannerPlugin):
    """AWS security scanner implementation."""
    
    def __init__(self):
        self.session = None
        self.checks = self._load_checks()

    def _load_checks(self) -> List[Dict[str, Any]]:
        """Load AWS security checks."""
        # TODO: Load from YAML configuration
        return [
            {
                "id": "aws-001",
                "name": "S3 Bucket Public Access",
                "description": "Check if S3 buckets have public access enabled",
                "severity": "high"
            },
            {
                "id": "aws-002",
                "name": "EC2 Security Groups",
                "description": "Check for overly permissive security groups",
                "severity": "medium"
            }
        ]

    def _initialize_session(self, profile: str = None, region: str = None) -> None:
        """Initialize AWS session."""
        if profile:
            self.session = boto3.Session(profile_name=profile, region_name=region)
        else:
            self.session = boto3.Session(region_name=region)

    def _check_s3_buckets(self) -> List[Dict[str, Any]]:
        """Check S3 bucket security."""
        s3 = self.session.client('s3')
        findings = []
        
        try:
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket['Name'])
                    if any(grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' 
                          for grant in acl['Grants']):
                        findings.append({
                            "check_id": "aws-001",
                            "resource": f"s3://{bucket['Name']}",
                            "status": "failed",
                            "message": "Bucket has public access enabled"
                        })
                except Exception as e:
                    findings.append({
                        "check_id": "aws-001",
                        "resource": f"s3://{bucket['Name']}",
                        "status": "error",
                        "message": f"Error checking bucket ACL: {str(e)}"
                    })
        except Exception as e:
            findings.append({
                "check_id": "aws-001",
                "resource": "s3",
                "status": "error",
                "message": f"Error listing buckets: {str(e)}"
            })
        
        return findings

    def _check_security_groups(self) -> List[Dict[str, Any]]:
        """Check EC2 security group configurations."""
        ec2 = self.session.client('ec2')
        findings = []
        
        try:
            security_groups = ec2.describe_security_groups()['SecurityGroups']
            for sg in security_groups:
                for permission in sg.get('IpPermissions', []):
                    if permission.get('IpRanges'):
                        for ip_range in permission['IpRanges']:
                            if ip_range['CidrIp'] == '0.0.0.0/0':
                                findings.append({
                                    "check_id": "aws-002",
                                    "resource": f"sg-{sg['GroupId']}",
                                    "status": "failed",
                                    "message": "Security group allows access from anywhere (0.0.0.0/0)"
                                })
        except Exception as e:
            findings.append({
                "check_id": "aws-002",
                "resource": "ec2",
                "status": "error",
                "message": f"Error checking security groups: {str(e)}"
            })
        
        return findings

    def scan(self, target: str, **kwargs) -> Dict[str, Any]:
        """Perform AWS security scan."""
        profile = kwargs.get('profile')
        region = kwargs.get('region')
        
        self._initialize_session(profile, region)
        
        findings = []
        findings.extend(self._check_s3_buckets())
        findings.extend(self._check_security_groups())
        
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

    def get_name(self) -> str:
        """Get scanner name."""
        return "aws"

    def get_description(self) -> str:
        """Get scanner description."""
        return "AWS infrastructure security scanner" 