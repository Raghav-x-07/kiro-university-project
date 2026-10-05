#!/usr/bin/env python3
"""
Cloud Asset & Health Auditor

A production-ready security posture assessment tool for AWS cloud infrastructure.
Evaluates S3 buckets, EC2 instances, and IAM policies against security best practices.

Author: Cloud Security Team
Version: 1.0.0
License: MIT
"""

import json
import logging
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Type definitions
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
AssetType = Literal["s3", "ec2", "iam"]
ComplianceScore = int  # Constrained to [0, 100]


# Exception hierarchy
class AuditorError(Exception):
    """Base exception for all auditor-related errors."""
    pass


class ValidationError(AuditorError):
    """Raised when input validation fails."""
    pass


class ScannerError(AuditorError):
    """Raised when scanner execution fails."""
    pass


class CalculationError(AuditorError):
    """Raised when score calculation fails."""
    pass


# Data models
@dataclass
class Finding:
    """Security finding with detailed metadata."""
    finding_id: str
    severity: Severity
    description: str
    asset_id: str
    asset_type: AssetType
    remediation: str
    compliance_impact: int

    def __post_init__(self) -> None:
        """Validate finding data after initialization."""
        if self.compliance_impact < 0:
            self.compliance_impact = 0
        elif self.compliance_impact > 25:
            self.compliance_impact = 25


@dataclass
class AuditResult:
    """Complete audit result with findings and metadata."""
    asset_id: str
    asset_type: AssetType
    findings: List[Finding]
    risk_score: int
    scan_timestamp: datetime

    def __post_init__(self) -> None:
        """Validate audit result bounds."""
        self.risk_score = max(0, min(100, self.risk_score))


# Mock data for realistic cloud infrastructure simulation
MOCK_S3_BUCKETS = [
    {
        "name": "company-public-website",
        "region": "us-east-1",
        "public_read_acl": True,
        "public_write_acl": False,
        "encryption_enabled": True,
        "versioning_enabled": True,
        "created_date": "2023-01-15"
    },
    {
        "name": "backup-storage-private",
        "region": "us-west-2",
        "public_read_acl": False,
        "public_write_acl": False,
        "encryption_enabled": False,
        "versioning_enabled": True,
        "created_date": "2023-03-22"
    },
    {
        "name": "logs-and-analytics",
        "region": "eu-west-1",
        "public_read_acl": False,
        "public_write_acl": False,
        "encryption_enabled": True,
        "versioning_enabled": False,
        "created_date": "2023-06-10"
    },
    {
        "name": "public-data-dump",
        "region": "us-east-1",
        "public_read_acl": True,
        "public_write_acl": True,
        "encryption_enabled": False,
        "versioning_enabled": False,
        "created_date": "2022-11-08"
    },
    {
        "name": "secure-documents",
        "region": "us-gov-west-1",
        "public_read_acl": False,
        "public_write_acl": False,
        "encryption_enabled": True,
        "versioning_enabled": True,
        "created_date": "2023-09-01"
    }
]

MOCK_EC2_INSTANCES = [
    {
        "instance_id": "i-1234567890abcdef0",
        "instance_type": "t3.micro",
        "state": "running",
        "public_ip": "203.0.113.42",
        "security_groups": [
            {
                "group_id": "sg-12345678",
                "group_name": "web-servers",
                "ingress_rules": [
                    {"protocol": "tcp", "port": 80, "cidr": "0.0.0.0/0"},
                    {"protocol": "tcp", "port": 443, "cidr": "0.0.0.0/0"},
                    {"protocol": "tcp", "port": 22, "cidr": "10.0.0.0/8"}
                ]
            }
        ]
    },
    {
        "instance_id": "i-abcdef1234567890",
        "instance_type": "m5.large",
        "state": "running",
        "public_ip": "203.0.113.100",
        "security_groups": [
            {
                "group_id": "sg-87654321",
                "group_name": "admin-access",
                "ingress_rules": [
                    {"protocol": "tcp", "port": 22, "cidr": "0.0.0.0/0"},
                    {"protocol": "tcp", "port": 3389, "cidr": "0.0.0.0/0"}
                ]
            }
        ]
    },
    {
        "instance_id": "i-fedcba0987654321",
        "instance_type": "t3.small",
        "state": "stopped",
        "public_ip": None,
        "security_groups": [
            {
                "group_id": "sg-11223344",
                "group_name": "private-servers",
                "ingress_rules": [
                    {"protocol": "tcp", "port": 3306, "cidr": "10.0.0.0/16"}
                ]
            }
        ]
    }
]

MOCK_IAM_POLICIES = [
    {
        "policy_name": "AdminAccess",
        "policy_arn": "arn:aws:iam::123456789012:policy/AdminAccess",
        "policy_document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        },
        "attached_entities": ["user:admin", "role:AdminRole"]
    },
    {
        "policy_name": "S3ReadOnlyAccess",
        "policy_arn": "arn:aws:iam::123456789012:policy/S3ReadOnlyAccess",
        "policy_document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }
            ]
        },
        "attached_entities": ["user:readonly"]
    },
    {
        "policy_name": "PowerUserAccess",
        "policy_arn": "arn:aws:iam::123456789012:policy/PowerUserAccess",
        "policy_document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                },
                {
                    "Effect": "Deny",
                    "Action": ["iam:*", "organizations:*"],
                    "Resource": "*"
                }
            ]
        },
        "attached_entities": ["role:PowerUserRole"]
    },
    {
        "policy_name": "WildcardResourcePolicy",
        "policy_arn": "arn:aws:iam::123456789012:policy/WildcardResourcePolicy",
        "policy_document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["ec2:DescribeInstances", "ec2:StartInstances"],
                    "Resource": "*"
                }
            ]
        },
        "attached_entities": ["user:devops"]
    }
]


# Validation functions
def validate_asset_type(asset: Dict[str, Any]) -> bool:
    """Validate asset dictionary structure at runtime."""
    required_fields = {"name", "region"} if "name" in asset else {"instance_id"} if "instance_id" in asset else {"policy_name"}
    return all(field in asset for field in required_fields)


def safe_cast_score(value: Any) -> int:
    """Safely cast and bound compliance scores."""
    try:
        score = int(value)
        return max(0, min(100, score))
    except (ValueError, TypeError):
        return 0


# Core audit functions
def audit_s3_bucket(bucket: Dict[str, Any]) -> Dict[str, Any]:
    """
    Audit S3 bucket for security misconfigurations.
    
    Args:
        bucket: Dictionary containing bucket metadata with keys:
            - name: Bucket name (str)
            - region: AWS region (str) 
            - public_read_acl: Public read access flag (bool)
            - public_write_acl: Public write access flag (bool)
            - encryption_enabled: Encryption status (bool)
    
    Returns:
        Dictionary containing audit results with keys:
            - findings: List of security findings
            - risk_score: Integer score [0-100]
            - recommendations: List of remediation steps
    
    Raises:
        ValidationError: If bucket dictionary is malformed
        ScannerError: If security analysis fails
    """
    try:
        if not validate_asset_type(bucket):
            raise ValidationError(f"Invalid bucket structure: {bucket.get('name', 'unknown')}")
        
        findings = []
        risk_score = 0
        recommendations = []
        
        # Check for public read ACL
        if bucket.get("public_read_acl", False):
            findings.append({
                "finding_id": f"S3-PUB-READ-{bucket['name'][:8]}",
                "severity": "HIGH",
                "description": f"Bucket '{bucket['name']}' allows public read access",
                "remediation": "Remove public read ACL and configure bucket policy for specific access"
            })
            risk_score += 15
            
        # Check for public write ACL
        if bucket.get("public_write_acl", False):
            findings.append({
                "finding_id": f"S3-PUB-WRITE-{bucket['name'][:8]}",
                "severity": "CRITICAL",
                "description": f"Bucket '{bucket['name']}' allows public write access",
                "remediation": "Immediately remove public write ACL to prevent data tampering"
            })
            risk_score += 25
            
        # Check encryption status
        if not bucket.get("encryption_enabled", False):
            findings.append({
                "finding_id": f"S3-NO-ENC-{bucket['name'][:8]}",
                "severity": "MEDIUM",
                "description": f"Bucket '{bucket['name']}' does not have encryption enabled",
                "remediation": "Enable server-side encryption with KMS or S3 managed keys"
            })
            risk_score += 10
            
        # Check versioning
        if not bucket.get("versioning_enabled", False):
            findings.append({
                "finding_id": f"S3-NO-VER-{bucket['name'][:8]}",
                "severity": "LOW",
                "description": f"Bucket '{bucket['name']}' does not have versioning enabled",
                "remediation": "Enable versioning to protect against accidental deletion"
            })
            risk_score += 5
            
        return {
            "asset_id": bucket["name"],
            "asset_type": "s3",
            "findings": findings,
            "risk_score": min(100, risk_score),
            "recommendations": recommendations
        }
        
    except ValidationError:
        raise
    except Exception as e:
        raise ScannerError(f"S3 scanner failed: {e}")


def audit_ec2_instance(instance: Dict[str, Any]) -> Dict[str, Any]:
    """
    Audit EC2 instance for security group misconfigurations.
    
    Args:
        instance: Dictionary containing instance metadata
    
    Returns:
        Dictionary with audit results
    """
    try:
        if not validate_asset_type(instance):
            raise ValidationError(f"Invalid instance structure: {instance.get('instance_id', 'unknown')}")
        
        findings = []
        risk_score = 0
        
        for sg in instance.get("security_groups", []):
            for rule in sg.get("ingress_rules", []):
                # Check for open SSH (port 22)
                if rule["port"] == 22 and rule["cidr"] == "0.0.0.0/0":
                    findings.append({
                        "finding_id": f"EC2-SSH-OPEN-{instance['instance_id'][-8:]}",
                        "severity": "CRITICAL", 
                        "description": f"Instance '{instance['instance_id']}' has SSH (port 22) open to the internet",
                        "remediation": "Restrict SSH access to specific IP ranges or use bastion hosts"
                    })
                    risk_score += 25
                    
                # Check for open RDP (port 3389)
                if rule["port"] == 3389 and rule["cidr"] == "0.0.0.0/0":
                    findings.append({
                        "finding_id": f"EC2-RDP-OPEN-{instance['instance_id'][-8:]}",
                        "severity": "CRITICAL",
                        "description": f"Instance '{instance['instance_id']}' has RDP (port 3389) open to the internet",
                        "remediation": "Restrict RDP access to specific IP ranges or use VPN"
                    })
                    risk_score += 25
        
        # Check if instance has public IP
        if instance.get("public_ip") and risk_score > 0:
            risk_score += 10  # Additional risk for public-facing instances with violations
            
        return {
            "asset_id": instance["instance_id"],
            "asset_type": "ec2", 
            "findings": findings,
            "risk_score": min(100, risk_score),
            "recommendations": []
        }
        
    except ValidationError:
        raise
    except Exception as e:
        raise ScannerError(f"EC2 scanner failed: {e}")


def audit_iam_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    """
    Audit IAM policy for overprivileged permissions.
    
    Args:
        policy: Dictionary containing policy metadata
    
    Returns:
        Dictionary with audit results
    """
    try:
        if not validate_asset_type(policy):
            raise ValidationError(f"Invalid policy structure: {policy.get('policy_name', 'unknown')}")
        
        findings = []
        risk_score = 0
        
        policy_doc = policy.get("policy_document", {})
        statements = policy_doc.get("Statement", [])
        
        if not isinstance(statements, list):
            statements = [statements]
            
        for statement in statements:
            if statement.get("Effect") == "Allow":
                actions = statement.get("Action", [])
                resources = statement.get("Resource", [])
                
                # Normalize to lists
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]
                
                # Check for wildcard actions
                if "*" in actions:
                    findings.append({
                        "finding_id": f"IAM-WILD-ACT-{policy['policy_name'][:8]}",
                        "severity": "CRITICAL",
                        "description": f"Policy '{policy['policy_name']}' allows all actions (*)",
                        "remediation": "Replace wildcard actions with specific, least-privilege permissions"
                    })
                    risk_score += 25
                    
                # Check for wildcard resources
                if "*" in resources:
                    findings.append({
                        "finding_id": f"IAM-WILD-RES-{policy['policy_name'][:8]}",
                        "severity": "HIGH",
                        "description": f"Policy '{policy['policy_name']}' allows access to all resources (*)",
                        "remediation": "Specify exact resource ARNs instead of wildcard access"
                    })
                    risk_score += 15
        
        return {
            "asset_id": policy["policy_name"],
            "asset_type": "iam",
            "findings": findings, 
            "risk_score": min(100, risk_score),
            "recommendations": []
        }
        
    except ValidationError:
        raise
    except Exception as e:
        raise ScannerError(f"IAM scanner failed: {e}")


def calculate_overall_score(findings: List[Dict[str, Any]]) -> int:
    """
    Calculate overall compliance score from audit findings.
    
    Args:
        findings: List of finding dictionaries
    
    Returns:
        Integer score between 0 and 100 (inclusive)
    """
    try:
        if not findings:
            return 100
        
        # Severity weights for score calculation
        severity_weights = {
            "CRITICAL": 25,
            "HIGH": 15,
            "MEDIUM": 10,
            "LOW": 5
        }
        
        total_deduction = 0
        for finding_group in findings:
            group_findings = finding_group.get("findings", [])
            for finding in group_findings:
                severity = finding.get("severity", "LOW")
                deduction = severity_weights.get(severity, 5)
                total_deduction += deduction
        
        # Cap deduction to prevent negative scores
        max_deduction = min(total_deduction, 100)
        score = 100 - max_deduction
        
        # Ensure score bounds [0, 100]
        return max(0, min(100, score))
        
    except Exception as e:
        logger.error(f"Score calculation failed: {e}")
        return 0


def generate_ascii_report(audit_results: List[Dict[str, Any]], overall_score: int) -> str:
    """
    Generate ASCII formatted compliance report.
    
    Args:
        audit_results: List of audit result dictionaries
        overall_score: Overall compliance score (0-100)
    
    Returns:
        Formatted ASCII report string
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Count totals
    total_assets = len(audit_results)
    total_violations = sum(len(result["findings"]) for result in audit_results)
    critical_issues = sum(1 for result in audit_results 
                         for finding in result["findings"] 
                         if finding.get("severity") == "CRITICAL")
    
    # Count by asset type
    s3_public = sum(1 for result in audit_results 
                   if result["asset_type"] == "s3" 
                   for finding in result["findings"] 
                   if "public" in finding.get("description", "").lower())
    
    s3_unencrypted = sum(1 for result in audit_results
                        if result["asset_type"] == "s3"
                        for finding in result["findings"]
                        if "encryption" in finding.get("description", "").lower())
    
    ec2_open_ssh = sum(1 for result in audit_results
                      if result["asset_type"] == "ec2"
                      for finding in result["findings"]
                      if "SSH" in finding.get("description", ""))
    
    ec2_open_rdp = sum(1 for result in audit_results
                      if result["asset_type"] == "ec2"
                      for finding in result["findings"] 
                      if "RDP" in finding.get("description", ""))
    
    iam_wildcard = sum(1 for result in audit_results
                      if result["asset_type"] == "iam"
                      for finding in result["findings"]
                      if "wildcard" in finding.get("description", "").lower())
    
    # Generate report
    report = f"""╔════════════════════════════════════════════╗
║        CLOUD SECURITY AUDIT REPORT        ║
╠════════════════════════════════════════════╣
║ Compliance Score: {overall_score:2d}%                     ║
║ Assets Scanned: {total_assets:3d}                       ║
║ Violations Found: {total_violations:2d}                      ║
║ Critical Issues: {critical_issues:1d}                        ║
║ Audit Date: {timestamp}          ║
╚════════════════════════════════════════════╝

┌─────────────────────────────────────────┐
│              FINDINGS SUMMARY            │
├─────────────────────────────────────────┤
│ S3 Buckets:                            │
│   • Public Buckets: {s3_public:1d}                  │
│   • Unencrypted: {s3_unencrypted:1d}                     │
│                                        │
│ EC2 Instances:                         │
│   • Open SSH (22): {ec2_open_ssh:1d}                   │
│   • Open RDP (3389): {ec2_open_rdp:1d}                 │
│                                        │  
│ IAM Policies:                          │
│   • Wildcard Policies: {iam_wildcard:1d}               │
│   • Overprivileged: {iam_wildcard:1d}                  │
└─────────────────────────────────────────┘

DETAILED FINDINGS:
"""
    
    # Add detailed findings
    for result in audit_results:
        for finding in result["findings"]:
            severity = finding.get("severity", "UNKNOWN")
            finding_id = finding.get("finding_id", "UNKNOWN")
            description = finding.get("description", "No description")
            remediation = finding.get("remediation", "No remediation provided")
            
            report += f"\n[{severity}] {finding_id}: {description}\n"
            report += f"  Asset: {result['asset_id']}\n"
            report += f"  Remediation: {remediation}\n"
    
    return report


def main() -> None:
    """Main CLI entrypoint for cloud security auditor."""
    logger.info("Starting Cloud Asset & Health Auditor v1.0.0")
    
    try:
        # Load and audit all mock assets
        audit_results = []
        
        # Audit S3 buckets
        for bucket in MOCK_S3_BUCKETS:
            try:
                result = audit_s3_bucket(bucket)
                audit_results.append(result)
                logger.info(f"Audited S3 bucket: {bucket['name']}")
            except (ValidationError, ScannerError) as e:
                logger.warning(f"Failed to audit bucket {bucket.get('name', 'unknown')}: {e}")
        
        # Audit EC2 instances  
        for instance in MOCK_EC2_INSTANCES:
            try:
                result = audit_ec2_instance(instance)
                audit_results.append(result)
                logger.info(f"Audited EC2 instance: {instance['instance_id']}")
            except (ValidationError, ScannerError) as e:
                logger.warning(f"Failed to audit instance {instance.get('instance_id', 'unknown')}: {e}")
        
        # Audit IAM policies
        for policy in MOCK_IAM_POLICIES:
            try:
                result = audit_iam_policy(policy)
                audit_results.append(result)
                logger.info(f"Audited IAM policy: {policy['policy_name']}")
            except (ValidationError, ScannerError) as e:
                logger.warning(f"Failed to audit policy {policy.get('policy_name', 'unknown')}: {e}")
        
        # Calculate overall compliance score
        overall_score = calculate_overall_score(audit_results)
        
        # Generate and display ASCII report
        report = generate_ascii_report(audit_results, overall_score)
        print(report)
        
        # Log summary
        total_findings = sum(len(result["findings"]) for result in audit_results)
        logger.info(f"Audit completed: {len(audit_results)} assets scanned, "
                   f"{total_findings} findings, score: {overall_score}%")
        
        # Exit with appropriate code
        sys.exit(0 if overall_score >= 80 else 1)
        
    except Exception as e:
        logger.error(f"Audit failed with unexpected error: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()