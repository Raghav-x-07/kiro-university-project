# Cloud Asset & Health Auditor - Architecture Guidelines

## Component Layout

### Core Architecture Principles
1. **Separation of Concerns**: Each scanner handles a single cloud service type
2. **Isolation**: Scanners operate independently without cross-dependencies
3. **Immutability**: All audit results are immutable data structures
4. **Testability**: Each component can be unit tested in isolation

### Module Organization
```
app.py                    # Main CLI entrypoint and orchestration
├── scanners/
│   ├── s3_scanner.py     # S3 bucket security analysis
│   ├── ec2_scanner.py    # EC2 instance and security group audit
│   └── iam_scanner.py    # IAM policy privilege analysis
├── models/
│   ├── assets.py         # Data models for cloud resources
│   ├── findings.py       # Security finding and result structures
│   └── scoring.py        # Compliance score calculation logic
├── reporting/
│   ├── formatter.py      # ASCII report generation
│   └── exporters.py      # JSON/CSV output handlers
└── utils/
    ├── mock_data.py      # Test data generators
    └── validators.py     # Input validation helpers
```

### Scanner Isolation Design

#### Independent Scanner Interface
```python
from abc import ABC, abstractmethod
from typing import List, Dict, Any

class CloudScanner(ABC):
    """Base interface ensuring scanner isolation and consistency."""
    
    @abstractmethod
    def scan_assets(self, assets: List[Dict[str, Any]]) -> List[Finding]:
        """Scan assets and return findings without side effects."""
        pass
    
    @abstractmethod
    def get_scanner_info(self) -> Dict[str, str]:
        """Return scanner metadata for audit trails."""
        pass
```

#### Scanner Implementation Requirements
- **No Shared State**: Each scanner maintains no global or class-level state
- **Pure Functions**: All scanning methods are pure functions with deterministic output
- **Error Isolation**: Scanner failures do not impact other scanners or overall audit
- **Resource Limits**: Each scanner operates within defined memory and time constraints

### Calculation Engine Isolation

#### Score Calculator Design
```python
class ComplianceCalculator:
    """Isolated scoring engine with no external dependencies."""
    
    @staticmethod
    def calculate_score(findings: List[Finding]) -> ComplianceScore:
        """Pure function for deterministic score calculation."""
        pass
    
    @staticmethod
    def validate_score_bounds(score: int) -> int:
        """Ensure score remains within [0,100] bounds."""
        return max(0, min(100, score))
```

#### Calculation Rules
- **Deterministic**: Same inputs always produce identical outputs
- **Bounded**: All scores constrained to [0,100] integer range
- **Weighted**: Findings impact score based on severity and asset criticality
- **Auditable**: Score calculation logic is transparent and traceable

## Dependency Constraints

### Allowed Dependencies (Development)
```python
# Testing frameworks
pytest>=7.4.0
hypothesis>=6.80.0

# Type checking and linting  
mypy>=1.5.0
black>=23.0.0
flake8>=6.0.0

# Documentation
sphinx>=7.0.0
```

### Prohibited Dependencies (Runtime)
```python
# ❌ Cloud SDKs - No runtime cloud API calls
boto3, azure-sdk, google-cloud

# ❌ Heavy frameworks - Keep it lightweight
django, flask, fastapi

# ❌ Database drivers - Use mock data only
psycopg2, pymongo, redis

# ❌ External service clients
requests, httpx, aiohttp
```

### Dependency Isolation Strategy
1. **Mock Data Layer**: All cloud asset data comes from static JSON files
2. **No Network Calls**: Zero external API dependencies during audit execution
3. **Minimal Standard Library**: Use only Python built-in modules for core logic
4. **Type Safety**: Leverage `typing` module for static analysis without runtime overhead

## Data Flow Architecture

### Audit Pipeline Flow
```
Input Assets (JSON)
       ↓
   Asset Validator
       ↓
   Scanner Router
    ↙    ↓    ↘
S3Scanner EC2Scanner IAMScanner
    ↘    ↓    ↙
   Finding Aggregator
       ↓
   Score Calculator
       ↓
   Report Generator
       ↓
Output (CLI/File)
```

### State Management
- **Immutable Assets**: Input asset data never modified during processing
- **Append-Only Findings**: Security findings accumulated in immutable lists
- **Stateless Components**: No component maintains state between audit runs
- **Thread Safety**: All components safe for concurrent execution

## Error Handling Strategy

### Defensive Programming Approach
```python
def audit_with_isolation(asset: dict) -> Optional[Finding]:
    """Example of isolated error handling."""
    try:
        validated_asset = validate_asset_schema(asset)
        return perform_security_scan(validated_asset)
    except ValidationError as e:
        logger.warning(f"Invalid asset schema: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected scanner error: {e}")
        return None
```

### Error Isolation Rules
1. **Fail Fast**: Invalid inputs rejected at component boundaries
2. **Graceful Degradation**: Single scanner failures don't halt entire audit
3. **Error Logging**: All errors logged with context but execution continues
4. **Default Fallbacks**: Missing or corrupted data gets safe default values

## Performance Guidelines

### Scalability Targets
- **Asset Volume**: Handle 10,000+ assets per audit run
- **Memory Usage**: <500MB peak memory for large audits
- **Execution Time**: <60 seconds for 1000 mixed assets
- **Concurrent Processing**: Support parallel scanner execution

### Optimization Strategies
- **Lazy Loading**: Load and process assets in batches
- **Generator Functions**: Use generators for large dataset iteration
- **Memory Pooling**: Reuse data structures where possible
- **Algorithmic Efficiency**: O(n) complexity for core scanning operations

## Security Considerations

### Secure Development Practices
1. **Input Validation**: All external data validated against strict schemas
2. **No Code Injection**: No dynamic code execution or eval() usage
3. **Safe Deserialization**: JSON parsing with size and depth limits
4. **Audit Trails**: All security findings include source attribution

### Privacy Protection
- **No PII Storage**: Asset metadata scrubbed of personal information
- **Secure Logging**: Log entries contain no sensitive cloud credentials
- **Data Minimization**: Only collect asset data necessary for security analysis