"""
Basic unit tests for Cloud Asset & Health Auditor.

These tests verify known baseline behavior and specific edge cases.
"""

import json
import pytest
from typing import Dict, Any, List

# Import functions from main app
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import (
    audit_s3_bucket,
    audit_ec2_instance,
    audit_iam_policy,
    calculate_overall_score,
    safe_cast_score,
    validate_asset_type,
    generate_ascii_report,
    Finding,
    AuditResult
)


class TestS3BucketAudit:
    """Unit tests for S3 bucket security scanning."""
    
    def test_audit_private_secure_bucket(self) -> None:
        """Test that a secure private bucket receives a clean audit."""
        bucket = {
            "name": "secure-private-bucket",
            "region": "us-west-2",
            "public_read_acl": False,
            "public_write_acl": False,
            "encryption_enabled": True,
            "versioning_enabled": True
        }
        
        result = audit_s3_bucket(bucket)
        
        assert result["asset_id"] == "secure-private-bucket"
        assert result["asset_type"] == "s3"
        assert result["risk_score"] == 0
        assert len(result["findings"]) == 0
    
    def test_audit_public_read_bucket(self) -> None:
        """Test detection of public read ACL."""
        bucket = {
            "name": "public-read-bucket", 
            "region": "us-east-1",
            "public_read_acl": True,
            "public_write_acl": False,
            "encryption_enabled": True,
            "versioning_enabled": True
        }
        
        result = audit_s3_bucket(bucket)
        
        assert result["risk_score"] == 15  # HIGH severity = 15 points
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "HIGH"
        assert "public read access" in result["findings"][0]["description"]
    
    def test_audit_public_write_bucket(self) -> None:
        """Test detection of critical public write ACL."""
        bucket = {
            "name": "public-write-bucket",
            "region": "us-east-1", 
            "public_read_acl": False,
            "public_write_acl": True,
            "encryption_enabled": True,
            "versioning_enabled": True
        }
        
        result = audit_s3_bucket(bucket)
        
        assert result["risk_score"] == 25  # CRITICAL severity = 25 points
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "CRITICAL"
        assert "public write access" in result["findings"][0]["description"]
    
    def test_audit_unencrypted_bucket(self) -> None:
        """Test detection of encryption issues."""
        bucket = {
            "name": "unencrypted-bucket",
            "region": "eu-west-1",
            "public_read_acl": False,
            "public_write_acl": False,
            "encryption_enabled": False,
            "versioning_enabled": True
        }
        
        result = audit_s3_bucket(bucket)
        
        assert result["risk_score"] == 10  # MEDIUM severity = 10 points
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "MEDIUM"
        assert "encryption" in result["findings"][0]["description"]
    
    def test_audit_multiple_issues_bucket(self) -> None:
        """Test bucket with multiple security issues."""
        bucket = {
            "name": "problematic-bucket",
            "region": "us-east-1",
            "public_read_acl": True,
            "public_write_acl": True,
            "encryption_enabled": False,
            "versioning_enabled": False
        }
        
        result = audit_s3_bucket(bucket)
        
        # Should have all four issues: public read (15) + public write (25) + 
        # no encryption (10) + no versioning (5) = 55 points, capped at 100
        assert result["risk_score"] == 55
        assert len(result["findings"]) == 4
        
        severities = [f["severity"] for f in result["findings"]]
        assert "CRITICAL" in severities  # public write
        assert "HIGH" in severities      # public read
        assert "MEDIUM" in severities    # no encryption
        assert "LOW" in severities       # no versioning


class TestEC2InstanceAudit:
    """Unit tests for EC2 instance security scanning."""
    
    def test_audit_secure_instance(self) -> None:
        """Test instance with secure security group configuration."""
        instance = {
            "instance_id": "i-secure123456789",
            "instance_type": "t3.micro",
            "state": "running",
            "public_ip": None,
            "security_groups": [
                {
                    "group_id": "sg-secure123",
                    "group_name": "secure-web",
                    "ingress_rules": [
                        {"protocol": "tcp", "port": 80, "cidr": "0.0.0.0/0"},
                        {"protocol": "tcp", "port": 443, "cidr": "0.0.0.0/0"},
                        {"protocol": "tcp", "port": 22, "cidr": "10.0.0.0/8"}
                    ]
                }
            ]
        }
        
        result = audit_ec2_instance(instance)
        
        assert result["asset_id"] == "i-secure123456789"
        assert result["asset_type"] == "ec2"
        assert result["risk_score"] == 0
        assert len(result["findings"]) == 0
    
    def test_audit_open_ssh_instance(self) -> None:
        """Test detection of open SSH access."""
        instance = {
            "instance_id": "i-openssh123456789",
            "instance_type": "t3.micro", 
            "state": "running",
            "public_ip": "203.0.113.100",
            "security_groups": [
                {
                    "group_id": "sg-openssh123",
                    "group_name": "admin-access",
                    "ingress_rules": [
                        {"protocol": "tcp", "port": 22, "cidr": "0.0.0.0/0"}
                    ]
                }
            ]
        }
        
        result = audit_ec2_instance(instance)
        
        # CRITICAL (25) + public IP additional risk (10) = 35
        assert result["risk_score"] == 35
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "CRITICAL"
        assert "SSH" in result["findings"][0]["description"]
        assert "internet" in result["findings"][0]["description"]
    
    def test_audit_open_rdp_instance(self) -> None:
        """Test detection of open RDP access."""
        instance = {
            "instance_id": "i-openrdp123456789",
            "instance_type": "m5.large",
            "state": "running", 
            "public_ip": "203.0.113.200",
            "security_groups": [
                {
                    "group_id": "sg-openrdp123",
                    "group_name": "windows-admin",
                    "ingress_rules": [
                        {"protocol": "tcp", "port": 3389, "cidr": "0.0.0.0/0"}
                    ]
                }
            ]
        }
        
        result = audit_ec2_instance(instance)
        
        assert result["risk_score"] == 35  # CRITICAL (25) + public IP (10)
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "CRITICAL"
        assert "RDP" in result["findings"][0]["description"]
    
    def test_audit_multiple_open_ports(self) -> None:
        """Test instance with both SSH and RDP open."""
        instance = {
            "instance_id": "i-multiopen123456789",
            "instance_type": "c5.xlarge",
            "state": "running",
            "public_ip": "203.0.113.50",
            "security_groups": [
                {
                    "group_id": "sg-multiopen123", 
                    "group_name": "unsafe-access",
                    "ingress_rules": [
                        {"protocol": "tcp", "port": 22, "cidr": "0.0.0.0/0"},
                        {"protocol": "tcp", "port": 3389, "cidr": "0.0.0.0/0"}
                    ]
                }
            ]
        }
        
        result = audit_ec2_instance(instance)
        
        # SSH CRITICAL (25) + RDP CRITICAL (25) + public IP (10) = 60
        assert result["risk_score"] == 60
        assert len(result["findings"]) == 2
        
        descriptions = [f["description"] for f in result["findings"]]
        assert any("SSH" in desc for desc in descriptions)
        assert any("RDP" in desc for desc in descriptions)


class TestIAMPolicyAudit:
    """Unit tests for IAM policy privilege scanning."""
    
    def test_audit_least_privilege_policy(self) -> None:
        """Test policy with proper least-privilege permissions."""
        policy = {
            "policy_name": "S3ReadOnlyPolicy",
            "policy_arn": "arn:aws:iam::123456789012:policy/S3ReadOnlyPolicy",
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
                    }
                ]
            }
        }
        
        result = audit_iam_policy(policy)
        
        assert result["asset_id"] == "S3ReadOnlyPolicy"
        assert result["asset_type"] == "iam"
        assert result["risk_score"] == 0
        assert len(result["findings"]) == 0
    
    def test_audit_wildcard_action_policy(self) -> None:
        """Test detection of wildcard actions."""
        policy = {
            "policy_name": "AdminPolicy",
            "policy_arn": "arn:aws:iam::123456789012:policy/AdminPolicy",
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "arn:aws:s3:::my-bucket/*"
                    }
                ]
            }
        }
        
        result = audit_iam_policy(policy)
        
        assert result["risk_score"] == 25  # CRITICAL severity
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "CRITICAL"
        assert "all actions (*)" in result["findings"][0]["description"]
    
    def test_audit_wildcard_resource_policy(self) -> None:
        """Test detection of wildcard resources."""
        policy = {
            "policy_name": "BroadResourcePolicy",
            "policy_arn": "arn:aws:iam::123456789012:policy/BroadResourcePolicy", 
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["ec2:DescribeInstances"],
                        "Resource": "*"
                    }
                ]
            }
        }
        
        result = audit_iam_policy(policy)
        
        assert result["risk_score"] == 15  # HIGH severity
        assert len(result["findings"]) == 1
        assert result["findings"][0]["severity"] == "HIGH"
        assert "all resources (*)" in result["findings"][0]["description"]
    
    def test_audit_full_admin_policy(self) -> None:
        """Test policy with both wildcard actions and resources."""
        policy = {
            "policy_name": "FullAdminPolicy",
            "policy_arn": "arn:aws:iam::123456789012:policy/FullAdminPolicy",
            "policy_document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*"
                    }
                ]
            }
        }
        
        result = audit_iam_policy(policy)
        
        # Wildcard action (25) + wildcard resource (15) = 40
        assert result["risk_score"] == 40
        assert len(result["findings"]) == 2
        
        severities = [f["severity"] for f in result["findings"]]
        assert "CRITICAL" in severities
        assert "HIGH" in severities


class TestComplianceScoreCalculation:
    """Unit tests for overall compliance score calculation."""
    
    def test_calculate_score_empty_findings(self) -> None:
        """Test score calculation with no findings."""
        score = calculate_overall_score([])
        assert score == 100
    
    def test_calculate_score_single_critical(self) -> None:
        """Test score calculation with one critical finding."""
        findings = [
            {
                "findings": [
                    {"severity": "CRITICAL", "description": "Critical issue"}
                ]
            }
        ]
        
        score = calculate_overall_score(findings)
        assert score == 75  # 100 - 25 (CRITICAL weight)
    
    def test_calculate_score_mixed_severities(self) -> None:
        """Test score calculation with mixed severity findings."""
        findings = [
            {
                "findings": [
                    {"severity": "CRITICAL", "description": "Critical issue"},
                    {"severity": "HIGH", "description": "High issue"}, 
                    {"severity": "MEDIUM", "description": "Medium issue"},
                    {"severity": "LOW", "description": "Low issue"}
                ]
            }
        ]
        
        # CRITICAL (25) + HIGH (15) + MEDIUM (10) + LOW (5) = 55
        score = calculate_overall_score(findings)
        assert score == 45  # 100 - 55
    
    def test_calculate_score_bounds_clamping(self) -> None:
        """Test that score calculation properly clamps to [0,100] bounds."""
        # Create excessive findings to test lower bound
        findings = [
            {
                "findings": [{"severity": "CRITICAL", "description": f"Issue {i}"}
                            for i in range(10)]
            }
        ]
        
        score = calculate_overall_score(findings)
        assert score == 0  # Should be clamped to 0 (10 * 25 = 250 deduction)


class TestUtilityFunctions:
    """Unit tests for utility and validation functions."""
    
    def test_safe_cast_score_valid_integers(self) -> None:
        """Test safe casting of valid integer values."""
        assert safe_cast_score(50) == 50
        assert safe_cast_score(0) == 0
        assert safe_cast_score(100) == 100
        assert safe_cast_score(-10) == 0  # Clamped to lower bound
        assert safe_cast_score(150) == 100  # Clamped to upper bound
    
    def test_safe_cast_score_invalid_types(self) -> None:
        """Test safe casting of invalid input types."""
        assert safe_cast_score("invalid") == 0
        assert safe_cast_score(None) == 0
        assert safe_cast_score([1, 2, 3]) == 0
        assert safe_cast_score({"score": 75}) == 0
    
    def test_validate_asset_type_s3(self) -> None:
        """Test asset validation for S3 buckets."""
        valid_bucket = {"name": "test-bucket", "region": "us-east-1"}
        assert validate_asset_type(valid_bucket) is True
        
        invalid_bucket = {"region": "us-east-1"}  # Missing name
        assert validate_asset_type(invalid_bucket) is False
    
    def test_validate_asset_type_ec2(self) -> None:
        """Test asset validation for EC2 instances.""" 
        valid_instance = {"instance_id": "i-123456789", "state": "running"}
        assert validate_asset_type(valid_instance) is True
        
        invalid_instance = {"state": "running"}  # Missing instance_id
        assert validate_asset_type(invalid_instance) is False
    
    def test_validate_asset_type_iam(self) -> None:
        """Test asset validation for IAM policies."""
        valid_policy = {"policy_name": "TestPolicy", "policy_arn": "arn:aws:..."}
        assert validate_asset_type(valid_policy) is True
        
        invalid_policy = {"policy_arn": "arn:aws:..."}  # Missing policy_name
        assert validate_asset_type(invalid_policy) is False


class TestReportGeneration:
    """Unit tests for ASCII report generation."""
    
    def test_generate_report_empty_results(self) -> None:
        """Test report generation with no audit results."""
        report = generate_ascii_report([], 100)
        
        assert "CLOUD SECURITY AUDIT REPORT" in report
        assert "Compliance Score: 100%" in report
        assert "Assets Scanned:   0" in report
        assert "Violations Found:  0" in report
        assert "Critical Issues: 0" in report
    
    def test_generate_report_with_findings(self) -> None:
        """Test report generation with actual findings."""
        audit_results = [
            {
                "asset_id": "test-bucket",
                "asset_type": "s3",
                "findings": [
                    {
                        "finding_id": "S3-001",
                        "severity": "HIGH",
                        "description": "Public bucket detected",
                        "remediation": "Remove public ACL"
                    }
                ]
            }
        ]
        
        report = generate_ascii_report(audit_results, 85)
        
        assert "Compliance Score: 85%" in report
        assert "Assets Scanned:   1" in report
        assert "Violations Found:  1" in report
        assert "[HIGH] S3-001: Public bucket detected" in report
        assert "Asset: test-bucket" in report
        assert "Remediation: Remove public ACL" in report


if __name__ == "__main__":
    pytest.main([__file__, "-v"])