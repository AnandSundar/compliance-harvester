"""
JSON Manifest Generator Module

This module generates a JSON manifest file containing run metadata
for the compliance evidence package.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any


logger = logging.getLogger(__name__)


def generate_manifest(
    findings: List[Dict[str, Any]],
    aws_account_id: str,
    region: str,
    tool_version: str = "1.0.0",
) -> Dict[str, Any]:
    """
    Generate the run manifest with metadata and summary.

    Args:
        findings: List of all compliance findings
        aws_account_id: AWS account ID
        region: AWS region
        tool_version: Version of the compliance harvester tool

    Returns:
        Dictionary containing the manifest
    """
    # Calculate statistics
    status_counts = {"PASS": 0, "FAIL": 0, "MANUAL_REVIEW": 0}
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    service_counts = {}

    for finding in findings:
        # Status counts
        status = finding.get("status", "UNKNOWN")
        if status in status_counts:
            status_counts[status] += 1

        # Severity counts
        severity = finding.get("severity", "UNKNOWN")
        if severity in severity_counts:
            severity_counts[severity] += 1

        # Service counts (determine from resource_id)
        resource_id = finding.get("resource_id", "")
        if resource_id.startswith("arn:aws:iam"):
            service = "IAM"
        elif resource_id.startswith("arn:aws:s3"):
            service = "S3"
        elif resource_id.startswith("arn:aws:cloudtrail"):
            service = "CloudTrail"
        elif resource_id.startswith("arn:aws:config"):
            service = "AWS Config"
        else:
            service = "Other"

        service_counts[service] = service_counts.get(service, 0) + 1

    # Build manifest
    manifest = {
        "manifest_version": "1.0",
        "tool_info": {
            "name": "compliance-harvester",
            "version": tool_version,
            "purpose": "SOC 2 & GDPR compliance evidence collection",
        },
        "run_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "aws_account_id": aws_account_id,
            "region": region,
            "timezone": "UTC",
        },
        "summary": {
            "total_checks": len(findings),
            "pass_count": status_counts["PASS"],
            "fail_count": status_counts["FAIL"],
            "manual_review_count": status_counts["MANUAL_REVIEW"],
            "pass_rate": round(
                (
                    (status_counts["PASS"] / len(findings) * 100)
                    if len(findings) > 0
                    else 0
                ),
                2,
            ),
        },
        "severity_breakdown": severity_counts,
        "service_breakdown": service_counts,
        "compliance_frameworks": {
            "soc2": {
                "trust_service_criteria": [
                    "CC6.1",
                    "CC6.3",
                    "CC6.7",
                    "CC6.8",
                    "CC7.2",
                    "CC7.3",
                    "CC7.4",
                ]
            },
            "gdpr": {
                "article": "Article 32",
                "sub_requirements": [
                    "Art. 32(1)(a)",
                    "Art. 32(1)(b)",
                    "Art. 32(1)(c)",
                    "Art. 32(1)(d)",
                ],
            },
        },
        "output_files": {
            "raw_data": ["raw/iam.json", "raw/s3.json", "raw/cloudtrail.json"],
            "reports": ["report.xlsx"],
        },
    }

    return manifest


def write_manifest(
    findings: List[Dict[str, Any]],
    output_path: str,
    aws_account_id: str,
    region: str,
    tool_version: str = "1.0.0",
) -> None:
    """
    Write the manifest to a JSON file.

    Args:
        findings: List of all compliance findings
        output_path: Path to save the manifest JSON file
        aws_account_id: AWS account ID
        region: AWS region
        tool_version: Version of the compliance harvester tool
    """
    logger.info(f"Generating manifest: {output_path}")

    manifest = generate_manifest(findings, aws_account_id, region, tool_version)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    logger.info(f"Manifest saved: {output_path}")
