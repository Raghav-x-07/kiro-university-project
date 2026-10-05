# Cloud Auditor Power

A comprehensive cloud security auditing power for Kiro that provides automated security posture assessment for AWS infrastructure.

## Overview

The Cloud Auditor Power delivers production-ready security scanning capabilities for AWS resources, focusing on the most critical security misconfigurations that lead to data breaches and compliance violations.

## Features

### 🔍 **Security Scanning Capabilities**
- **S3 Bucket Analysis**: Detects public ACLs, encryption status, and access policies
- **EC2 Instance Assessment**: Reviews security groups for open SSH/RDP access  
- **IAM Policy Evaluation**: Identifies wildcard permissions and privilege escalation risks
- **Compliance Scoring**: Generates 0-100 security posture scores with detailed breakdowns

### 🎯 **Key Security Checks**
- Public S3 bucket detection (read/write ACLs)
- Open ingress rules on ports 22 (SSH) and 3389 (RDP)
- IAM policies with wildcard (*) actions or resources
- Unencrypted storage and transit configurations
- Overprivileged service accounts and roles

### 📊 **Reporting & Output**
- ASCII formatted compliance reports
- Detailed finding descriptions with remediation steps
- Risk-based prioritization (CRITICAL, HIGH, MEDIUM, LOW)
- JSON export for programmatic integration
- Executive summary dashboards

## Installation

### Prerequisites
- Python 3.8+ installed
- Kiro development environment
- No external cloud credentials required (uses mock data)

### Setup Instructions

1. **Install the Power**
   ```bash
   # Power will be automatically available in Kiro Powers catalog
   # Or install manually:
   cp -r .kiro/powers/cloud-auditor ~/.kiro/powers/
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify Installation**
   ```bash
   python app.py --help
   ```

## Usage

### Basic Audit Execution
```bash
# Run complete security audit
python app.py

# Run with verbose output  
python app.py --verbose

# Export results to JSON
python app.py --format json --output audit-results.json
```

### CLI Options
```
Usage: python app.py [OPTIONS]

Options:
  --format TEXT     Output format: ascii, json, csv (default: ascii)
  --output TEXT     Output file path (default: stdout)
  --verbose         Enable detailed logging and diagnostics
  --help           Show this help message and exit
```

### Example Output
```
╔════════════════════════════════════════════╗
║        CLOUD SECURITY AUDIT REPORT        ║
╠════════════════════════════════════════════╣
║ Compliance Score: 67%                     ║
║ Assets Scanned: 156                       ║
║ Violations Found: 8                       ║
║ Critical Issues: 2                        ║
║ Audit Date: 2026-10-05 21:45:32          ║
╚════════════════════════════════════════════╝

┌─────────────────────────────────────────┐
│              FINDINGS SUMMARY            │
├─────────────────────────────────────────┤
│ S3 Buckets:                            │
│   • Public Buckets: 2                  │
│   • Unencrypted: 3                     │
│                                        │
│ EC2 Instances:                         │
│   • Open SSH (22): 1                   │
│   • Open RDP (3389): 0                 │
│                                        │  
│ IAM Policies:                          │
│   • Wildcard Policies: 2               │
│   • Overprivileged: 4                  │
└─────────────────────────────────────────┘

[CRITICAL] S3-001: Public S3 Bucket Detected
  Bucket: company-backup-bucket
  Issue: Bucket allows public read access  
  Impact: Sensitive data exposure risk
  Remediation: Remove public ACL and configure bucket policy

[HIGH] EC2-002: Open SSH Access
  Instance: i-1234567890abcdef0
  Issue: Security group allows 0.0.0.0/0 on port 22
  Impact: Unauthorized access risk
  Remediation: Restrict SSH access to specific IP ranges
```

## Permissions Required

### Kiro Power Permissions
- **File System Access**: Read-write access to local directories for report generation
- **Network Access**: DISABLED - All scanning uses mock data (no cloud API calls)
- **Cloud APIs**: DISABLED - Zero external dependencies for security

### Mock Data Sources
The power includes realistic mock data representing:
- 50+ S3 buckets with various security configurations
- 30+ EC2 instances with diverse security group setups  
- 25+ IAM policies ranging from least-privilege to wildcard admin
- Simulated multi-account and multi-region AWS environments

## Configuration

### Power Configuration (power.json)
```json
{
  "mockDataPath": "data/",
  "outputFormat": "ascii", 
  "scoringAlgorithm": "weighted-severity",
  "maxAssetsPerScan": 10000,
  "timeoutSeconds": 300
}
```

### Custom Scoring Weights
```python
# Modify scoring weights in app.py
SEVERITY_WEIGHTS = {
    "CRITICAL": 25,  # Major security exposure
    "HIGH": 15,      # Significant risk
    "MEDIUM": 10,    # Moderate concern  
    "LOW": 5         # Minor issue
}
```

## Development & Testing

### Running Tests
```bash
# Run all tests
pytest tests/

# Run property-based tests only
pytest tests/test_properties.py -v

# Run with coverage report
pytest --cov=app --cov-report=html tests/
```

### Code Quality Checks
```bash
# Type checking
mypy app.py

# Code formatting
black app.py tests/

# Linting
flake8 app.py tests/
```

## Integration with Kiro

### Automatic Hooks
The power includes quality gate hooks that automatically:
- Validate Python syntax on file saves
- Run type checking with mypy
- Execute basic compilation checks
- Trigger test suites on code changes

### MCP Server Integration  
- Provides audit context to other Kiro components
- Exposes scanning capabilities through Model Context Protocol
- Enables seamless integration with Kiro workflows

### Custom Agent Support
- Specialized cloud-auditor agent for autonomous security analysis
- Property-based testing validation for compliance calculations
- Automated remediation recommendation generation

## Troubleshooting

### Common Issues

**"ModuleNotFoundError: No module named 'hypothesis'"**
```bash
# Install missing dependencies
pip install hypothesis>=6.80.0 pytest>=7.4.0
```

**"Permission denied writing output file"**
```bash
# Check file permissions or write to different directory
python app.py --output ~/audit-results.json
```

**"No mock data found"**
```bash
# Verify data directory exists with mock assets
ls -la data/mock_assets.json
```

### Debug Mode
```bash
# Enable detailed logging
python app.py --verbose 2>&1 | tee debug.log
```

## Support & Contributing

### Documentation
- [Architecture Guide](.kiro/steering/architecture.md)
- [Coding Standards](.kiro/steering/coding-standards.md) 
- [Development Roadmap](.kiro/steering/roadmap.md)

### Issue Reporting
1. Include Python version and operating system
2. Provide full error message and stack trace  
3. Attach debug log output if available
4. Include steps to reproduce the issue

### Contributing
1. Fork the repository
2. Follow PEP 8 coding standards
3. Add property-based tests for new features
4. Update documentation and type hints
5. Submit pull request with detailed description

## License & Security

### Security Considerations
- **Zero Cloud Credentials**: Power never accesses real cloud APIs
- **Mock Data Only**: All scanning uses simulated infrastructure data
- **Input Validation**: Strict schema validation on all inputs
- **Safe Deserialization**: JSON parsing with size and depth limits

### Privacy Protection
- No personal or sensitive data collection
- Audit logs contain no cloud credentials
- Asset metadata scrubbed of PII
- Local-only execution with no external network calls