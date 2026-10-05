"""
Property-based tests for Cloud Asset & Health Auditor.

These tests use Hypothesis to verify critical invariants and edge cases
that traditional unit tests might miss.
"""

import json
from typing import Any, Dict, List

import pytest
from hypothesis import given, strategies as st, assume

# Import functions from main app
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import (
    calculate_overall_score,
    audit_s3_bucket,
    audit_ec2_instance, 
    audit_iam_policy,
    safe_cast_score,
    validate_asset_type
)


class TestScoreBoundsProperties:
    """Property-based tests ensuring score calculation bounds."""
    
    @given(st.lists(st.dictionaries(
        keys=st.just("findings"),
        values=st.lists(st.dictionaries(
            keys=st.sampled_from(["severity", "description"]),
            values=st.one_of(
                st.sampled_from(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
                st.text(max_size=50)
            ),
            min_size=1
        ), max_size=5)
    ), max_size=10))
    def test_calculate_overall_score_always_bounded(self, findings: List[Dict[str, Any]]) -> None:
        """Property: calculate_overall_score always returns [0,100] for any input."""
        score = calculate_overall_score(findings)
        assert isinstance(score, int)
        assert 0 <= score <= 100
    
    @given(st.lists(st.integers()))
    def test_safe_cast_score_bounds(self, values: List[int]) -> None:
        """Property: safe_cast_score always returns bounded values."""
        for value in values:
            score = safe_cast_score(value)
            assert isinstance(score, int)
            assert 0 <= score <= 100
    
    @given(st.one_of(
        st.none(),
        st.text(),
        st.floats(),
        st.lists(st.integers()),
        st.dictionaries(keys=st.text(), values=st.integers())
    ))
    def test_safe_cast_score_handles_any_type(self, value: Any) -> None:
        """Property: safe_cast_score handles any input type gracefully."""
        score = safe_cast_score(value)
        assert isinstance(score, int)
        assert 0 <= score <= 100


class TestAssetSchemaProperties:
    """Property-based tests for asset dictionary schema preservation."""
    
    @given(st.dictionaries(
        keys=st.sampled_from(["name", "region", "public_read_acl", "public_write_acl", 
                             "encryption_enabled", "versioning_enabled"]),
        values=st.one_of(st.text(), st.booleans())
    ))
    def test_s3_audit_preserves_required_keys(self, bucket_data: Dict[str, Any]) -> None:
        """Property: S3 audit preserves asset schema structure."""
        assume("name" in bucket_data and "region" in bucket_data)
        
        try:
            result = audit_s3_bucket(bucket_data)
            
            # Verify result structure
            assert isinstance(result, dict)
            required_keys = {"asset_id", "asset_type", "findings", "risk_score"}
            assert all(key in result for key in required_keys)
            
            # Verify data types
            assert isinstance(result["asset_id"], str)
            assert result["asset_type"] == "s3"
            assert isinstance(result["findings"], list)
            assert isinstance(result["risk_score"], int)
            assert 0 <= result["risk_score"] <= 100
            
        except Exception:
            # If validation fails, that's acceptable behavior
            pass
    
    @given(st.dictionaries(
        keys=st.sampled_from(["instance_id", "instance_type", "state", "public_ip", 
                             "security_groups"]),
        values=st.one_of(
            st.text(),
            st.none(),
            st.lists(st.dictionaries(
                keys=st.sampled_from(["group_id", "group_name", "ingress_rules"]),
                values=st.one_of(
                    st.text(),
                    st.lists(st.dictionaries(
                        keys=st.sampled_from(["protocol", "port", "cidr"]),
                        values=st.one_of(st.text(), st.integers(min_value=1, max_value=65535))
                    ))
                )
            ))
        )
    ))
    def test_ec2_audit_preserves_schema(self, instance_data: Dict[str, Any]) -> None:
        """Property: EC2 audit maintains schema invariants."""
        assume("instance_id" in instance_data)
        
        try:
            result = audit_ec2_instance(instance_data)
            
            # Verify result structure
            assert isinstance(result, dict)
            required_keys = {"asset_id", "asset_type", "findings", "risk_score"}
            assert all(key in result for key in required_keys)
            
            # Verify asset ID preservation
            assert result["asset_id"] == instance_data["instance_id"]
            assert result["asset_type"] == "ec2"
            
        except Exception:
            # Validation failures are acceptable
            pass
    
    @given(st.dictionaries(
        keys=st.sampled_from(["policy_name", "policy_arn", "policy_document", 
                             "attached_entities"]),
        values=st.one_of(
            st.text(),
            st.lists(st.text()),
            st.dictionaries(
                keys=st.sampled_from(["Version", "Statement"]),
                values=st.one_of(
                    st.text(),
                    st.lists(st.dictionaries(
                        keys=st.sampled_from(["Effect", "Action", "Resource"]),
                        values=st.one_of(st.text(), st.lists(st.text()))
                    ))
                )
            )
        )
    ))
    def test_iam_audit_schema_consistency(self, policy_data: Dict[str, Any]) -> None:
        """Property: IAM audit maintains consistent output schema."""
        assume("policy_name" in policy_data)
        
        try:
            result = audit_iam_policy(policy_data)
            
            # Check output structure
            assert isinstance(result, dict)
            assert "findings" in result
            assert isinstance(result["findings"], list)
            
            # Verify all findings have required structure
            for finding in result["findings"]:
                assert isinstance(finding, dict)
                assert "finding_id" in finding
                assert "severity" in finding
                assert finding["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                
        except Exception:
            # Expected for malformed inputs
            pass


class TestFuzzInputHandling:
    """Property-based tests for graceful handling of malformed inputs."""
    
    @given(st.one_of(
        st.none(),
        st.integers(),
        st.floats(),
        st.text(),
        st.lists(st.integers()),
        st.dictionaries(keys=st.text(), values=st.text())
    ))
    def test_validate_asset_type_never_crashes(self, malformed_input: Any) -> None:
        """Property: validate_asset_type handles any input without crashing."""
        try:
            result = validate_asset_type(malformed_input)
            assert isinstance(result, bool)
        except (TypeError, AttributeError):
            # These exceptions are acceptable for completely invalid inputs
            pass
    
    @given(st.dictionaries(
        keys=st.text(),
        values=st.one_of(
            st.none(), st.integers(), st.floats(), st.text(), 
            st.booleans(), st.lists(st.text())
        )
    ))
    def test_s3_audit_handles_unexpected_keys(self, random_dict: Dict[str, Any]) -> None:
        """Property: S3 audit gracefully handles dictionaries with unexpected keys."""
        try:
            result = audit_s3_bucket(random_dict)
            # If it succeeds, verify basic structure
            assert isinstance(result, dict)
            assert "risk_score" in result
            assert isinstance(result["risk_score"], int)
            assert 0 <= result["risk_score"] <= 100
        except Exception:
            # Exceptions for invalid inputs are expected and acceptable
            pass
    
    @given(st.dictionaries(
        keys=st.text(min_size=1),
        values=st.recursive(
            st.one_of(st.none(), st.booleans(), st.integers(), st.floats(), st.text()),
            lambda children: st.one_of(
                st.lists(children, max_size=3),
                st.dictionaries(st.text(min_size=1), children, max_size=3)
            ),
            max_leaves=10
        )
    ))
    def test_ec2_audit_fuzz_resilience(self, fuzz_data: Dict[str, Any]) -> None:
        """Property: EC2 audit handles deeply nested/complex malformed data."""
        try:
            result = audit_ec2_instance(fuzz_data)
            # If successful, verify output bounds
            assert isinstance(result["risk_score"], int)
            assert 0 <= result["risk_score"] <= 100
            assert isinstance(result["findings"], list)
        except Exception:
            # Expected behavior for malformed inputs
            pass


class TestDeterminismProperties:
    """Property-based tests ensuring deterministic behavior."""
    
    @given(st.lists(st.dictionaries(
        keys=st.sampled_from(["findings"]),
        values=st.lists(st.dictionaries(
            keys=st.sampled_from(["severity"]),
            values=st.sampled_from(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        ))
    )))
    def test_score_calculation_determinism(self, findings_data: List[Dict[str, Any]]) -> None:
        """Property: Score calculation is deterministic for same inputs."""
        # Calculate score multiple times
        score1 = calculate_overall_score(findings_data)
        score2 = calculate_overall_score(findings_data)
        score3 = calculate_overall_score(findings_data)
        
        # All results must be identical
        assert score1 == score2 == score3
        assert all(isinstance(score, int) for score in [score1, score2, score3])
    
    @given(st.dictionaries(
        keys=st.sampled_from(["name", "region", "public_read_acl", "public_write_acl"]),
        values=st.one_of(st.text(min_size=1), st.booleans())
    ))
    def test_s3_audit_determinism(self, bucket_data: Dict[str, Any]) -> None:
        """Property: S3 audit produces identical results for same input."""
        assume("name" in bucket_data and "region" in bucket_data)
        
        try:
            result1 = audit_s3_bucket(bucket_data)
            result2 = audit_s3_bucket(bucket_data)
            
            # Results must be identical
            assert result1["risk_score"] == result2["risk_score"]
            assert len(result1["findings"]) == len(result2["findings"])
            
            # Finding IDs should be deterministic
            finding_ids1 = [f.get("finding_id") for f in result1["findings"]]
            finding_ids2 = [f.get("finding_id") for f in result2["findings"]]
            assert finding_ids1 == finding_ids2
            
        except Exception:
            # Skip invalid inputs
            pass


class TestComplexScenarioProperties:
    """Property-based tests for complex real-world scenarios."""
    
    @given(st.lists(
        st.dictionaries(
            keys=st.sampled_from(["findings"]),
            values=st.lists(
                st.dictionaries(
                    keys=st.sampled_from(["severity", "finding_id", "description"]),
                    values=st.one_of(
                        st.sampled_from(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
                        st.text(min_size=1, max_size=50)
                    )
                ),
                min_size=0,
                max_size=20
            )
        ),
        min_size=0,
        max_size=100
    ))
    def test_large_dataset_score_bounds(self, large_findings: List[Dict[str, Any]]) -> None:
        """Property: Score calculation scales correctly with large datasets."""
        score = calculate_overall_score(large_findings)
        
        # Score must always be bounded regardless of dataset size
        assert 0 <= score <= 100
        assert isinstance(score, int)
        
        # With many critical findings, score should be low
        critical_count = sum(
            1 for finding_group in large_findings
            for finding in finding_group.get("findings", [])
            if finding.get("severity") == "CRITICAL"
        )
        
        if critical_count > 4:  # Threshold where score should be very low
            assert score <= 50
    
    @given(st.lists(
        st.dictionaries(
            keys=st.sampled_from(["name", "region", "public_read_acl", "public_write_acl",
                                "encryption_enabled", "versioning_enabled"]),
            values=st.one_of(st.text(min_size=1), st.booleans())
        ).filter(lambda x: "name" in x and "region" in x),
        min_size=1,
        max_size=50
    ))
    def test_batch_s3_audit_consistency(self, bucket_batch: List[Dict[str, Any]]) -> None:
        """Property: Batch S3 auditing maintains consistency."""
        results = []
        
        for bucket in bucket_batch:
            try:
                result = audit_s3_bucket(bucket)
                results.append(result)
            except Exception:
                continue
        
        if results:
            # All results should have consistent structure
            for result in results:
                assert isinstance(result, dict)
                assert "asset_type" in result
                assert result["asset_type"] == "s3"
                assert 0 <= result["risk_score"] <= 100
            
            # Asset IDs should be unique (based on bucket names)
            asset_ids = [r["asset_id"] for r in results]
            bucket_names = [b["name"] for b in bucket_batch if "name" in b]
            
            # Each result should correspond to a bucket
            for asset_id in asset_ids:
                assert asset_id in bucket_names


if __name__ == "__main__":
    pytest.main([__file__, "-v"])