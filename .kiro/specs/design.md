# Cloud Asset & Health Auditor - Design Specification

## Architecture Overview

### System Components
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   CLI Interface │────│  Audit Engine    │────│  Score Calculator│
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Report Generator│    │  Asset Scanners  │    │  Data Models    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Component Responsibilities
- **CLI Interface**: Entry point, argument parsing, output formatting
- **Audit Engine**: Orchestrates scanning workflow and result aggregation
- **Asset Scanners**: Specialized modules for S3, EC2, and IAM analysis
- **Score Calculator**: Implements compliance scoring algorithms
- **Report Generator**: ASCII report formatting and compliance summaries
- **Data Models**: Type definitions and schema validation

## Data Model Schemas

### S3 Bucket Model
```python
@dataclass
class S3Bucket:
    name: str
    region: str
    public_read_acl: bool
    public_write_acl: bool
    encryption_enabled: bool
    versioning_enabled: bool
    created_date: datetime
```

### EC2 Instance Model
```python
@dataclass
class EC2Instance:
    instance_id: str
    instance_type: str
    state: str
    security_groups: List[SecurityGroup]
    vpc_id: str
    subnet_id: str
    public_ip: Optional[str]
```

### IAM Policy Model
```python
@dataclass
class IAMPolicy:
    policy_name: str
    policy_arn: str
    policy_document: dict
    attached_entities: List[str]
    creation_date: datetime
    last_used: Optional[datetime]
```

## Compliance Score Formulas

### Base Score Calculation
```python
def calculate_base_score(total_assets: int, violations: List[Finding]) -> int:
    """
    Base score formula: 100 - (weighted_violations / total_assets * 100)
    Constraint: 0 ≤ score ≤ 100
    """
    if total_assets == 0:
        return 100
    
    weighted_score = sum(finding.compliance_impact for finding in violations)
    deduction_percentage = min(100, (weighted_score / total_assets) * 10)
    
    return max(0, min(100, int(100 - deduction_percentage)))
```

### Severity Weights
- **CRITICAL**: 25 points
- **HIGH**: 15 points  
- **MEDIUM**: 10 points
- **LOW**: 5 points

### Risk Multipliers
- Public-facing assets: 1.5x multiplier
- Production environment: 2.0x multiplier
- Compliance-regulated: 1.8x multiplier

## CLI Output Structure

### Summary Report Format
```
╔════════════════════════════════════════════╗
║        CLOUD SECURITY AUDIT REPORT        ║
╠════════════════════════════════════════════╣
║ Compliance Score: XX%                     ║
║ Assets Scanned: XXX                       ║
║ Violations Found: XX                      ║
║ Critical Issues: X                        ║
║ Audit Date: YYYY-MM-DD HH:MM:SS          ║
╚════════════════════════════════════════════╝

┌─────────────────────────────────────────┐
│              FINDINGS SUMMARY            │
├─────────────────────────────────────────┤
│ S3 Buckets:                            │
│   • Public Buckets: X                  │
│   • Unencrypted: X                     │
│                                        │
│ EC2 Instances:                         │
│   • Open SSH (22): X                   │
│   • Open RDP (3389): X                 │
│                                        │  
│ IAM Policies:                          │
│   • Wildcard Policies: X               │
│   • Overprivileged: X                  │
└─────────────────────────────────────────┘
```

### Detailed Findings Format
```
[CRITICAL] S3-001: Public S3 Bucket Detected
  Bucket: my-public-bucket
  Issue: Bucket allows public read access
  Impact: Data exposure risk
  Remediation: Remove public ACL and configure bucket policy
  
[HIGH] EC2-002: Open SSH Access
  Instance: i-1234567890abcdef0
  Issue: Security group allows 0.0.0.0/0 on port 22
  Impact: Unauthorized access risk
  Remediation: Restrict SSH access to specific IP ranges
```

## Integration Points

### External Dependencies (Development Only)
- **pytest**: Unit testing framework
- **hypothesis**: Property-based testing
- **typing**: Static type annotations

### Mock Data Sources
- Simulated AWS asset inventory (JSON format)
- Predefined security group configurations
- Sample IAM policy documents
- Test bucket configurations with various ACL settings

## Extensibility Design

### Plugin Architecture
```python
class AuditPlugin(ABC):
    @abstractmethod
    def scan_asset(self, asset: dict) -> List[Finding]:
        pass
    
    @abstractmethod
    def get_supported_types(self) -> List[str]:
        pass
```

### Future Cloud Provider Support
- Interface abstractions for Azure and GCP
- Provider-specific scanner implementations
- Unified finding and scoring models