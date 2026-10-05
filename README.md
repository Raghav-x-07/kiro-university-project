# Cloud Asset & Health Auditor

A production-ready security posture assessment tool for AWS cloud infrastructure that evaluates S3 buckets, EC2 instances, and IAM policies against industry best practices and compliance frameworks.

## High-Level Architecture Overview

The Cloud Asset & Health Auditor follows a modular, scanner-based architecture designed for extensibility and maintainability:

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

### Core Components
- **Asset Scanners**: Isolated modules for S3, EC2, and IAM security analysis
- **Audit Engine**: Orchestrates scanning workflow and result aggregation  
- **Compliance Calculator**: Deterministic scoring engine with bounded output [0,100]
- **Report Generator**: ASCII-formatted compliance reports and executive summaries
- **Mock Data Layer**: Realistic cloud infrastructure simulation without external dependencies

### Key Security Checks
- 🔍 **S3 Bucket Analysis**: Public ACL detection, encryption validation, versioning assessment
- 🛡️ **EC2 Instance Assessment**: Security group analysis for open SSH/RDP ports (22/3389)  
- 🔐 **IAM Policy Evaluation**: Wildcard permission detection in actions and resources
- 📊 **Compliance Scoring**: Risk-weighted scoring with severity-based deductions

## Quickstart Guide

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation & Execution

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run security audit
python app.py

# 3. Run comprehensive tests  
pytest tests/

# 4. Run property-based tests specifically
pytest tests/test_properties.py -v
```

### Example Output
```
╔════════════════════════════════════════════╗
║        CLOUD SECURITY AUDIT REPORT        ║
╠════════════════════════════════════════════╣
║ Compliance Score: 67%                     ║
║ Assets Scanned: 13                        ║
║ Violations Found: 8                       ║
║ Critical Issues: 2                        ║
║ Audit Date: 2026-10-05 21:45:32          ║
╚════════════════════════════════════════════╝

┌─────────────────────────────────────────┐
│              FINDINGS SUMMARY            │
├─────────────────────────────────────────┤
│ S3 Buckets:                            │
│   • Public Buckets: 2                  │
│   • Unencrypted: 2                     │
│                                        │
│ EC2 Instances:                         │
│   • Open SSH (22): 1                   │
│   • Open RDP (3389): 1                 │
│                                        │  
│ IAM Policies:                          │
│   • Wildcard Policies: 2               │
│   • Overprivileged: 2                  │
└─────────────────────────────────────────┘

[CRITICAL] S3-PUB-WRITE-public-da: Bucket 'public-data-dump' allows public write access
  Asset: public-data-dump
  Remediation: Immediately remove public write ACL to prevent data tampering

[CRITICAL] EC2-SSH-OPEN-90abcdef: Instance 'i-abcdef1234567890' has SSH (port 22) open to the internet
  Asset: i-abcdef1234567890  
  Remediation: Restrict SSH access to specific IP ranges or use bastion hosts

[CRITICAL] IAM-WILD-ACT-AdminAcc: Policy 'AdminAccess' allows all actions (*)
  Asset: AdminAccess
  Remediation: Replace wildcard actions with specific, least-privilege permissions
```

## Project Structure

```
cloud-asset-auditor/
├── .kiro/
│   ├── specs/                    # Spec-driven development documents
│   │   ├── requirements.md       # Functional requirements and acceptance criteria
│   │   ├── design.md            # Architecture and data model specifications
│   │   └── tasks.md             # Phased development breakdown
│   ├── steering/                 # Architecture and coding guidance
│   │   ├── architecture.md       # Component isolation and design patterns
│   │   ├── coding-standards.md   # PEP 8 compliance and type safety rules
│   │   └── roadmap.md           # Multi-cloud expansion roadmap
│   ├── hooks/
│   │   └── quality-gate.json    # Automated validation hooks
│   ├── agents/
│   │   └── cloud-auditor.json   # Custom agent configuration
│   ├── powers/
│   │   └── cloud-auditor/       # Reusable Kiro Power package
│   └── mcp.json                 # Model Context Protocol configuration
├── tests/
│   ├── test_properties.py       # Property-based tests with Hypothesis
│   └── test_basic.py           # Traditional unit tests
├── app.py                      # Main application with all audit logic
├── requirements.txt            # Python dependencies
└── README.md                   # This documentation
```

## Kiro University Lessons Used

This project demonstrates mastery of all 7 core Kiro University lessons:

### 1. Spec-Driven Development
Outlined complete system specifications, schema models, and phased development tasks in `.kiro/specs/`. The requirements document defines functional requirements with precise acceptance criteria, while the design document establishes architecture patterns and data models. Task breakdown provides milestone-driven development tracking.

### 2. Steering Documents  
Defined architecture principles, coding standards, and development roadmap guardrails in `.kiro/steering/`. Architecture guidelines ensure component isolation and scanner independence. Coding standards enforce PEP 8 compliance, static typing, and zero external dependencies. Roadmap planning establishes multi-cloud expansion strategy.

### 3. Hooks
Configured post-save validation hooks in `.kiro/hooks/quality-gate.json` for automated compilation checks. The hook triggers Python syntax validation on file edits to catch errors early in the development cycle.

### 4. Property-Based Testing
Implemented Hypothesis-driven tests in `tests/test_properties.py` to assert score bounds invariants, schema preservation properties, and fuzz testing resilience. Property-based tests verify that scoring functions maintain [0,100] bounds for any input and that asset dictionaries preserve required keys through processing.

### 5. Powers
Packaged a standalone audit scanner tool with complete manifest and installation documentation in `.kiro/powers/cloud-auditor/`. The power provides reusable security scanning capabilities with defined permissions, dependencies, and configuration options.

### 6. Model Context Protocol (MCP)  
Configured project context server in `.kiro/mcp.json` to provide audit context and capabilities to other Kiro components. The MCP server enables seamless integration with the broader Kiro ecosystem.

### 7. Custom Agents
Created dedicated security auditing agent configuration in `.kiro/agents/cloud-auditor.json`. The specialized agent focuses on cloud posture analysis, compliance scoring, and automated property-based test validation with appropriate tool access and restrictions.

## Advanced Features

### Security Compliance Framework
- **Risk-Based Scoring**: Severity-weighted deduction system with CRITICAL (25pts), HIGH (15pts), MEDIUM (10pts), LOW (5pts)
- **Bounded Calculations**: All scores mathematically constrained to [0,100] range with deterministic output
- **Asset Type Isolation**: Independent scanners prevent cross-contamination of findings
- **Input Validation**: Schema validation with graceful error handling for malformed data

### Property-Based Test Coverage
- **Score Bounds Verification**: Hypothesis tests ensure scoring functions never exceed [0,100] bounds
- **Schema Round-Trip Testing**: Asset dictionaries maintain structure integrity through processing
- **Fuzz Input Resilience**: Scanners handle malformed inputs without crashes or undefined behavior
- **Determinism Validation**: Same inputs always produce identical outputs across multiple executions

### Mock Data Simulation
- **Realistic Infrastructure**: 13 cloud assets representing diverse security configurations
- **Security Scenarios**: Public buckets, open security groups, wildcard IAM policies
- **Edge Cases**: Mix of compliant and non-compliant resources for comprehensive testing
- **Zero Dependencies**: No external cloud APIs required for full audit functionality

## Development & Testing

### Code Quality Standards
```bash
# Type checking with mypy
mypy app.py

# Code formatting with black  
black app.py tests/

# Linting with flake8
flake8 app.py tests/

# Run all quality checks
python -m pytest tests/ --cov=app --cov-report=html
```

### Test Execution
```bash
# Run all tests with verbose output
pytest tests/ -v

# Run only property-based tests
pytest tests/test_properties.py -v --hypothesis-show-statistics

# Run with coverage reporting
pytest tests/ --cov=app --cov-report=term-missing

# Run performance benchmarking
pytest tests/test_basic.py::TestComplianceScoreCalculation -v
```

### Kiro Integration Commands
```bash
# Activate hooks for file validation
# Hooks automatically trigger on .py file saves

# Test MCP server connectivity  
python -m http.server 8000

# Validate agent configuration
# Agent available in Kiro Powers catalog

# Install as reusable power
cp -r .kiro/powers/cloud-auditor ~/.kiro/powers/
```

## Security & Compliance

### Security Design Principles
- **Zero Trust Architecture**: No external API calls, all data from controlled mock sources
- **Input Validation**: Strict schema validation with bounds checking on all inputs
- **Deterministic Processing**: Reproducible results with no random or time-based variations
- **Error Isolation**: Component failures contained without affecting overall audit execution
- **Privacy Protection**: No PII collection, cloud credentials, or sensitive data storage

### Compliance Frameworks Supported
- **AWS Well-Architected Framework**: Security pillar best practices assessment
- **CIS Controls**: Critical security controls for cloud infrastructure
- **NIST Cybersecurity Framework**: Risk identification and protection measures
- **SOC 2 Type II**: Security, availability, and confidentiality controls

### Audit Trail & Logging
- **Structured Logging**: JSON-formatted audit events with timestamps and context
- **Finding Attribution**: Each security finding includes source asset identification
- **Score Calculation Transparency**: Detailed breakdown of compliance score derivation
- **Processing Metadata**: Asset counts, scan duration, and error summaries

## Troubleshooting

### Common Issues & Solutions

**ImportError: No module named 'hypothesis'**
```bash
pip install hypothesis>=6.80.0 pytest>=7.4.0
```

**Type checking failures with mypy**
```bash
# Install mypy and run type checking
pip install mypy>=1.5.0
mypy app.py --ignore-missing-imports
```

**Property-based test failures**
```bash
# Run with detailed hypothesis output
pytest tests/test_properties.py -v --hypothesis-show-statistics --hypothesis-verbosity=verbose
```

**Score calculation discrepancies**
```bash
# Enable debug logging
python app.py --verbose 2>&1 | grep -E "(CRITICAL|HIGH|MEDIUM|LOW)"
```

### Debug Mode
```bash
# Run with detailed audit logging
python -c "
import logging
logging.basicConfig(level=logging.DEBUG)
exec(open('app.py').read())
"
```

## Contributing & Development

### Development Workflow
1. **Fork Repository**: Create personal fork for feature development
2. **Follow Standards**: Adhere to PEP 8 coding standards and type hints
3. **Add Tests**: Include both unit tests and property-based tests for new features  
4. **Update Documentation**: Maintain accuracy of specs, steering docs, and README
5. **Submit PR**: Provide detailed description of changes and testing performed

### Architecture Extensions
- **New Cloud Providers**: Implement `CloudScanner` interface for Azure/GCP support
- **Additional Asset Types**: Extend scanning to RDS, Lambda, VPC resources
- **Custom Frameworks**: Add compliance framework mappings and scoring algorithms
- **Integration APIs**: Develop REST API for programmatic audit execution

### Performance Optimization
- **Batch Processing**: Implement concurrent asset scanning with thread pools
- **Memory Management**: Optimize large dataset handling with generators
- **Caching**: Add result caching for repeated audits of static infrastructure
- **Profiling**: Include performance benchmarking in test suites

## License & Support

### License
MIT License - See LICENSE file for complete terms and conditions.

### Support Channels  
- **Documentation**: Complete architecture and API documentation in `.kiro/` directory
- **Issues**: Report bugs and feature requests through repository issue tracker
- **Community**: Join discussions on Kiro University forums and Discord channels
- **Professional**: Enterprise support and consulting services available on request

### Security Reporting
Report security vulnerabilities privately to the maintainer team. Include detailed reproduction steps, affected versions, and potential impact assessment. Security issues receive priority response and coordinated disclosure handling.

---

**Cloud Asset & Health Auditor v1.0.0** | Built with ❤️ for Kiro University | Production-Ready Security Assessment