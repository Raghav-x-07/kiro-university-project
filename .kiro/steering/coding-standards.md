# Cloud Asset & Health Auditor - Coding Standards

## PEP 8 Compliance Guidelines

### Code Formatting Rules
- **Line Length**: Maximum 88 characters (Black formatter standard)
- **Indentation**: 4 spaces, no tabs
- **Import Organization**: Standard library, third-party, local imports (separated by blank lines)
- **Function Naming**: `snake_case` for functions and variables
- **Class Naming**: `PascalCase` for classes and exceptions
- **Constant Naming**: `UPPER_SNAKE_CASE` for module-level constants

### Import Standards
```python
# Standard library imports
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional, Union, Literal

# Third-party imports (development only)
import pytest
from hypothesis import given, strategies as st

# Local application imports
from models.assets import S3Bucket, EC2Instance, IAMPolicy
from models.findings import Finding, Severity
```

## Static Type Hints Requirements

### Mandatory Type Annotations
All functions, methods, and class attributes MUST include type hints:

```python
from typing import Dict, List, Optional, Union, Literal, TypedDict

# Function signatures
def audit_s3_bucket(bucket: Dict[str, Any]) -> Dict[str, Any]:
    """Audit S3 bucket with complete type safety."""
    pass

# Class definitions with typed attributes  
@dataclass
class Finding:
    finding_id: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    description: str
    asset_id: str
    compliance_impact: int

# Complex type definitions
AssetInventory = Dict[str, List[Dict[str, Any]]]
ScanResult = Union[Finding, None]
ComplianceScore = int  # Constrained to [0, 100]
```

### Type Validation Patterns
```python
def validate_asset_type(asset: Dict[str, Any]) -> bool:
    """Validate asset dictionary structure at runtime."""
    required_fields = {"id", "type", "metadata"}
    return all(field in asset for field in required_fields)

def safe_cast_score(value: Any) -> int:
    """Safely cast and bound compliance scores."""
    try:
        score = int(value)
        return max(0, min(100, score))
    except (ValueError, TypeError):
        return 0
```

## Deterministic Error Handling

### Exception Hierarchy
```python
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
```

### Error Handling Patterns
```python
def robust_audit_function(asset: Dict[str, Any]) -> Optional[Finding]:
    """Demonstrates deterministic error handling approach."""
    try:
        # Input validation with specific error messages
        if not validate_asset_type(asset):
            raise ValidationError(f"Invalid asset structure: {asset.get('id', 'unknown')}")
        
        # Core business logic with controlled exceptions
        result = perform_security_analysis(asset)
        
        # Output validation
        if not isinstance(result, dict):
            raise CalculationError("Scanner returned non-dict result")
            
        return create_finding_from_result(result)
        
    except ValidationError as e:
        logging.warning(f"Asset validation failed: {e}")
        return None
    except CalculationError as e:
        logging.error(f"Calculation error: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error in audit: {e}")
        return None
```

### Logging Standards
```python
import logging
from typing import Any

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def log_audit_event(event_type: str, asset_id: str, details: Dict[str, Any]) -> None:
    """Standardized audit event logging."""
    logger.info(
        "Audit Event",
        extra={
            "event_type": event_type,
            "asset_id": asset_id,
            "details": details
        }
    )
```

## Zero External Dependencies Policy

### Allowed Standard Library Modules
```python
# Core Python modules (runtime approved)
import json          # JSON parsing and serialization
import logging       # Structured logging
import sys           # System-specific parameters
import os            # Operating system interface
import datetime      # Date and time handling
from abc import ABC, abstractmethod  # Abstract base classes
from dataclasses import dataclass    # Data class definitions
from typing import *                 # Type hints and annotations
```

### Prohibited External Libraries (Runtime)
```python
# ❌ Cloud service SDKs
import boto3         # AWS SDK
import azure.mgmt    # Azure SDK  
import google.cloud  # GCP SDK

# ❌ HTTP clients
import requests      # HTTP library
import urllib3       # HTTP client
import httpx         # Async HTTP client

# ❌ Database connections
import psycopg2      # PostgreSQL
import pymongo       # MongoDB
import redis         # Redis client
```

### Mock Data Strategy
```python
# ✅ Acceptable approach: Static mock data
MOCK_S3_BUCKETS = [
    {
        "name": "my-public-bucket",
        "region": "us-east-1", 
        "public_read_acl": True,
        "public_write_acl": False,
        "encryption_enabled": False
    }
]

# ✅ Acceptable: JSON file loading
def load_mock_assets() -> Dict[str, List[Dict[str, Any]]]:
    """Load mock asset data from JSON files."""
    with open("data/mock_assets.json", "r") as f:
        return json.load(f)
```

## Code Quality Enforcement

### Pre-commit Quality Gates
```python
# File: quality_checks.py
def run_static_analysis() -> bool:
    """Run all static analysis tools."""
    checks = [
        run_mypy_check(),
        run_black_format_check(), 
        run_flake8_lint(),
        run_pytest_tests()
    ]
    return all(checks)

def run_mypy_check() -> bool:
    """Type checking with mypy."""
    import subprocess
    result = subprocess.run(["mypy", "app.py"], capture_output=True)
    return result.returncode == 0
```

### Documentation Standards
```python
def audit_s3_bucket(bucket: Dict[str, Any]) -> Dict[str, Any]:
    """
    Audit S3 bucket for security misconfigurations.
    
    Args:
        bucket: Dictionary containing bucket metadata with keys:
            - name: Bucket name (str)
            - region: AWS region (str) 
            - public_read_acl: Public read access flag (bool)
            - public_write_acl: Public write access flag (bool)
    
    Returns:
        Dictionary containing audit results with keys:
            - findings: List of security findings
            - risk_score: Integer score [0-100]
            - recommendations: List of remediation steps
    
    Raises:
        ValidationError: If bucket dictionary is malformed
        ScannerError: If security analysis fails
    
    Example:
        >>> bucket = {"name": "test-bucket", "region": "us-east-1", 
        ...          "public_read_acl": True, "public_write_acl": False}
        >>> result = audit_s3_bucket(bucket)
        >>> assert result["risk_score"] >= 0
    """
    pass
```

## Testing Requirements

### Unit Test Standards
```python
import pytest
from typing import Dict, Any
from hypothesis import given, strategies as st

class TestS3Scanner:
    """Test suite for S3 bucket scanner."""
    
    def test_audit_private_bucket(self) -> None:
        """Test that private buckets receive clean audit results."""
        bucket = {
            "name": "private-bucket",
            "region": "us-west-2",
            "public_read_acl": False,
            "public_write_acl": False
        }
        result = audit_s3_bucket(bucket)
        assert result["risk_score"] == 0
        assert len(result["findings"]) == 0
    
    @given(st.text(), st.booleans(), st.booleans())
    def test_audit_bucket_type_safety(self, name: str, read_acl: bool, write_acl: bool) -> None:
        """Property-based test ensuring type safety."""
        bucket = {
            "name": name,
            "region": "us-east-1", 
            "public_read_acl": read_acl,
            "public_write_acl": write_acl
        }
        result = audit_s3_bucket(bucket)
        assert isinstance(result, dict)
        assert isinstance(result["risk_score"], int)
        assert 0 <= result["risk_score"] <= 100
```

### Property-Based Testing Requirements
- **Score Bounds**: All scoring functions must maintain [0,100] bounds for any input
- **Schema Invariants**: Asset dictionaries must preserve required keys through processing
- **Error Resilience**: Functions must handle malformed inputs gracefully
- **Determinism**: Same inputs must always produce identical outputs