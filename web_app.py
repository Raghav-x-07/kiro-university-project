#!/usr/bin/env python3
"""
Cloud Asset & Health Auditor - Web Interface

A Flask web application providing a professional dashboard for cloud security auditing.
Maintains all Kiro University requirements while adding web functionality.

Author: Cloud Security Team
Version: 1.0.0
License: MIT
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List

from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from werkzeug.exceptions import BadRequest

# Import all audit functions from the main application
from app import (
    audit_s3_bucket,
    audit_ec2_instance, 
    audit_iam_policy,
    calculate_overall_score,
    MOCK_S3_BUCKETS,
    MOCK_EC2_INSTANCES,
    MOCK_IAM_POLICIES,
    generate_ascii_report
)

# Configure Flask application
app = Flask(__name__)
app.secret_key = 'cloud-auditor-secure-key-2026'
app.config['DEBUG'] = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@app.route('/')
def dashboard():
    """Main dashboard showing audit overview and statistics."""
    try:
        # Run quick audit for dashboard stats
        audit_results = run_complete_audit()
        
        # Calculate summary statistics
        total_assets = len(audit_results)
        total_findings = sum(len(result["findings"]) for result in audit_results)
        critical_count = sum(1 for result in audit_results 
                           for finding in result["findings"] 
                           if finding.get("severity") == "CRITICAL")
        high_count = sum(1 for result in audit_results
                        for finding in result["findings"]
                        if finding.get("severity") == "HIGH")
        
        overall_score = calculate_overall_score(audit_results)
        
        # Asset breakdown
        s3_assets = len([r for r in audit_results if r["asset_type"] == "s3"])
        ec2_assets = len([r for r in audit_results if r["asset_type"] == "ec2"])
        iam_assets = len([r for r in audit_results if r["asset_type"] == "iam"])
        
        # Risk distribution
        risk_distribution = {
            "CRITICAL": critical_count,
            "HIGH": high_count,
            "MEDIUM": sum(1 for result in audit_results
                         for finding in result["findings"]
                         if finding.get("severity") == "MEDIUM"),
            "LOW": sum(1 for result in audit_results
                      for finding in result["findings"]
                      if finding.get("severity") == "LOW")
        }
        
        dashboard_data = {
            "total_assets": total_assets,
            "total_findings": total_findings,
            "compliance_score": overall_score,
            "critical_issues": critical_count,
            "high_issues": high_count,
            "asset_breakdown": {
                "s3": s3_assets,
                "ec2": ec2_assets, 
                "iam": iam_assets
            },
            "risk_distribution": risk_distribution,
            "last_scan": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "danger" if overall_score < 30 else "warning" if overall_score < 70 else "success"
        }
        
        return render_template('dashboard.html', data=dashboard_data)
        
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash(f"Dashboard loading error: {e}", "error")
        return render_template('error.html', error=str(e))


@app.route('/audit')
def audit_page():
    """Full audit page with detailed findings and reports."""
    try:
        # Run complete audit
        audit_results = run_complete_audit()
        overall_score = calculate_overall_score(audit_results)
        
        # Generate ASCII report for display
        ascii_report = generate_ascii_report(audit_results, overall_score)
        
        # Organize findings by severity and type
        findings_by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        findings_by_type = {"s3": [], "ec2": [], "iam": []}
        
        for result in audit_results:
            asset_type = result["asset_type"]
            for finding in result["findings"]:
                severity = finding.get("severity", "LOW")
                finding_with_asset = {
                    **finding,
                    "asset_id": result["asset_id"],
                    "asset_type": asset_type
                }
                findings_by_severity[severity].append(finding_with_asset)
                findings_by_type[asset_type].append(finding_with_asset)
        
        audit_data = {
            "results": audit_results,
            "overall_score": overall_score,
            "ascii_report": ascii_report,
            "findings_by_severity": findings_by_severity,
            "findings_by_type": findings_by_type,
            "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_assets": len(audit_results),
            "total_findings": sum(len(result["findings"]) for result in audit_results)
        }
        
        return render_template('audit.html', data=audit_data)
        
    except Exception as e:
        logger.error(f"Audit page error: {e}")
        flash(f"Audit execution error: {e}", "error")
        return render_template('error.html', error=str(e))


@app.route('/api/audit', methods=['GET', 'POST'])
def api_audit():
    """REST API endpoint for running audits programmatically."""
    try:
        if request.method == 'POST':
            # Handle custom asset data if provided
            custom_data = request.get_json() if request.is_json else None
            
            if custom_data:
                # Validate and audit custom assets
                audit_results = []
                for asset in custom_data.get('assets', []):
                    asset_type = asset.get('type')
                    if asset_type == 's3':
                        result = audit_s3_bucket(asset)
                        audit_results.append(result)
                    elif asset_type == 'ec2':
                        result = audit_ec2_instance(asset)
                        audit_results.append(result)
                    elif asset_type == 'iam':
                        result = audit_iam_policy(asset)
                        audit_results.append(result)
            else:
                # Use default mock data
                audit_results = run_complete_audit()
        else:
            # GET request - return current audit
            audit_results = run_complete_audit()
        
        overall_score = calculate_overall_score(audit_results)
        
        api_response = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "audit_results": audit_results,
            "overall_score": overall_score,
            "summary": {
                "total_assets": len(audit_results),
                "total_findings": sum(len(r["findings"]) for r in audit_results),
                "critical_issues": sum(1 for r in audit_results
                                     for f in r["findings"]
                                     if f.get("severity") == "CRITICAL"),
                "compliance_status": "FAIL" if overall_score < 50 else "WARN" if overall_score < 80 else "PASS"
            }
        }
        
        return jsonify(api_response)
        
    except Exception as e:
        logger.error(f"API audit error: {e}")
        return jsonify({
            "status": "error",
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500


@app.route('/assets')
def assets_page():
    """Asset inventory and individual asset details."""
    try:
        # Organize all assets by type
        all_assets = {
            "s3": [{"name": b["name"], "region": b["region"], 
                   "public_read": b.get("public_read_acl", False),
                   "public_write": b.get("public_write_acl", False),
                   "encrypted": b.get("encryption_enabled", False)} 
                  for b in MOCK_S3_BUCKETS],
            "ec2": [{"instance_id": i["instance_id"], "type": i["instance_type"],
                    "state": i["state"], "public_ip": i.get("public_ip")} 
                   for i in MOCK_EC2_INSTANCES],
            "iam": [{"policy_name": p["policy_name"], "arn": p["policy_arn"],
                    "entities": len(p.get("attached_entities", []))} 
                   for p in MOCK_IAM_POLICIES]
        }
        
        # Calculate asset statistics
        asset_stats = {
            "total": len(MOCK_S3_BUCKETS) + len(MOCK_EC2_INSTANCES) + len(MOCK_IAM_POLICIES),
            "s3_count": len(MOCK_S3_BUCKETS),
            "ec2_count": len(MOCK_EC2_INSTANCES),
            "iam_count": len(MOCK_IAM_POLICIES)
        }
        
        return render_template('assets.html', assets=all_assets, stats=asset_stats)
        
    except Exception as e:
        logger.error(f"Assets page error: {e}")
        flash(f"Asset loading error: {e}", "error")
        return render_template('error.html', error=str(e))


@app.route('/kiro-university')
def kiro_university():
    """Kiro University lessons demonstration page."""
    try:
        lessons_data = {
            "lesson1": {
                "title": "Spec-Driven Development",
                "description": "Complete system specifications with requirements, design, and tasks",
                "files": [".kiro/specs/requirements.md", ".kiro/specs/design.md", ".kiro/specs/tasks.md"],
                "status": "✅ Completed"
            },
            "lesson2": {
                "title": "Steering Documents", 
                "description": "Architecture guidelines, coding standards, and roadmap planning",
                "files": [".kiro/steering/architecture.md", ".kiro/steering/coding-standards.md", ".kiro/steering/roadmap.md"],
                "status": "✅ Completed"
            },
            "lesson3": {
                "title": "Hooks",
                "description": "Quality gate validation and automated file validation",
                "files": [".kiro/hooks/quality-gate.json"],
                "status": "✅ Completed"
            },
            "lesson4": {
                "title": "Property-Based Testing",
                "description": "Hypothesis tests for bounds validation and schema integrity",
                "files": ["tests/test_properties.py"],
                "status": "✅ Completed"
            },
            "lesson5": {
                "title": "Powers",
                "description": "Reusable audit scanner package with installation docs",
                "files": [".kiro/powers/cloud-auditor/power.json", ".kiro/powers/cloud-auditor/README.md"],
                "status": "✅ Completed"
            },
            "lesson6": {
                "title": "Model Context Protocol (MCP)",
                "description": "Context server configuration for Kiro ecosystem integration",
                "files": [".kiro/mcp.json"],
                "status": "✅ Completed"
            },
            "lesson7": {
                "title": "Custom Agents",
                "description": "Specialized security auditing agent configuration",
                "files": [".kiro/agents/cloud-auditor.json"],
                "status": "✅ Completed"
            }
        }
        
        return render_template('kiro_university.html', lessons=lessons_data)
        
    except Exception as e:
        logger.error(f"Kiro University page error: {e}")
        flash(f"Kiro University page error: {e}", "error")
        return render_template('error.html', error=str(e))


@app.route('/api/test')
def api_test():
    """API endpoint for running the test suite."""
    try:
        import subprocess
        
        # Run the test suite
        result = subprocess.run(
            ["python", "-m", "pytest", "tests/", "--tb=short", "-q"],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        test_response = {
            "status": "success" if result.returncode == 0 else "failure",
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "timestamp": datetime.now().isoformat()
        }
        
        return jsonify(test_response)
        
    except subprocess.TimeoutExpired:
        return jsonify({
            "status": "error",
            "message": "Test execution timed out",
            "timestamp": datetime.now().isoformat()
        }), 500
    except Exception as e:
        return jsonify({
            "status": "error", 
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500


def run_complete_audit() -> List[Dict[str, Any]]:
    """Run complete audit on all mock assets."""
    audit_results = []
    
    # Audit S3 buckets
    for bucket in MOCK_S3_BUCKETS:
        try:
            result = audit_s3_bucket(bucket)
            audit_results.append(result)
        except Exception as e:
            logger.warning(f"Failed to audit S3 bucket {bucket.get('name', 'unknown')}: {e}")
    
    # Audit EC2 instances
    for instance in MOCK_EC2_INSTANCES:
        try:
            result = audit_ec2_instance(instance)
            audit_results.append(result)
        except Exception as e:
            logger.warning(f"Failed to audit EC2 instance {instance.get('instance_id', 'unknown')}: {e}")
    
    # Audit IAM policies
    for policy in MOCK_IAM_POLICIES:
        try:
            result = audit_iam_policy(policy)
            audit_results.append(result)
        except Exception as e:
            logger.warning(f"Failed to audit IAM policy {policy.get('policy_name', 'unknown')}: {e}")
    
    return audit_results


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return render_template('error.html', error="Page not found"), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {error}")
    return render_template('error.html', error="Internal server error"), 500


if __name__ == '__main__':
    print("🚀 Starting Cloud Asset & Health Auditor Web Interface")
    print("📊 Access the dashboard at: http://localhost:5000")
    print("🔍 API documentation at: http://localhost:5000/api/audit")
    print("🎓 Kiro University lessons at: http://localhost:5000/kiro-university")
    
    # Run the Flask development server
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    )