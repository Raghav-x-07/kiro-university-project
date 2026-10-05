# Cloud Asset & Health Auditor - Requirements Specification

## Overview
The Cloud Asset & Health Auditor is a production-ready security posture assessment tool that evaluates AWS cloud infrastructure against industry best practices and compliance frameworks.

## Functional Requirements

### FR-001: S3 Bucket Security Assessment
- **Requirement**: Scan S3 buckets for public access control lists (ACLs)
- **Criteria**: Identify buckets with public read/write permissions
- **Output**: Risk level (HIGH/MEDIUM/LOW) and remediation recommendations
- **Schema**: `{"bucket_name": str, "public_acl": bool, "risk_level": str, "findings": list}`

### FR-002: EC2 Instance Security Group Analysis
- **Requirement**: Evaluate EC2 security groups for open ingress rules
- **Criteria**: Flag rules allowing 0.0.0.0/0 access on ports 22 (SSH) and 3389 (RDP)
- **Output**: Security violations with affected instances and ports
- **Schema**: `{"instance_id": str, "security_groups": list, "open_ports": list, "violations": list}`

### FR-003: IAM Policy Wildcard Detection
- **Requirement**: Analyze IAM policies for overprivileged wildcard (*) permissions
- **Criteria**: Detect policies with Action: "*" or Resource: "*"
- **Output**: Policy violations with risk assessment
- **Schema**: `{"policy_name": str, "has_wildcard": bool, "wildcard_actions": list, "wildcard_resources": list}`

### FR-004: Compliance Score Calculation
- **Requirement**: Generate overall security posture score
- **Formula**: `score = max(0, min(100, 100 - (violations_count * 10)))`
- **Constraints**: $0 \le score \le 100$
- **Output**: Integer percentage representing compliance level

## Security Posture Evaluation Metrics

### Scoring Matrix
| Violation Type | Point Deduction | Weight |
|----------------|----------------|--------|
| Public S3 Bucket | -15 points | HIGH |
| Open SSH/RDP | -20 points | CRITICAL |
| IAM Wildcard Policy | -25 points | CRITICAL |
| Minor Misconfig | -5 points | LOW |

### Acceptance Criteria
- **AC-001**: All audit functions must return structured dictionaries matching defined schemas
- **AC-002**: Score calculation must be deterministic and bounded [0,100]
- **AC-003**: CLI output must include ASCII report formatting
- **AC-004**: Zero external cloud API dependencies during runtime
- **AC-005**: All functions must handle malformed input gracefully

## Schema Boundaries

### Asset Schema
```python
AssetSchema = {
    "id": str,
    "type": Literal["s3", "ec2", "iam"],
    "metadata": dict,
    "findings": list[dict],
    "risk_score": int
}
```

### Finding Schema
```python
FindingSchema = {
    "finding_id": str,
    "severity": Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    "description": str,
    "remediation": str,
    "compliance_impact": int
}
```

## Non-Functional Requirements
- **Performance**: Audit 1000+ assets within 30 seconds
- **Reliability**: 99.9% uptime for batch processing
- **Maintainability**: Type hints on all functions, PEP 8 compliance
- **Testability**: 100% property-based test coverage on core logic