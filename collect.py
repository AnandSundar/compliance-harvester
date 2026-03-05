#!/usr/bin/env python3
"""
Compliance Harvester - CLI Entry Point

A CLI tool that collects AWS cloud evidence for SOC 2 Trust Service Criteria
and GDPR Article 32 controls in a single run and exports an auditor-ready
evidence package.

Usage:
    python collect.py --profile default --region us-east-1 --output ./output
    python collect.py --dry-run
    python collect.py --checks iam,s3

For help:
    python collect.py --help
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

import yaml
import boto3
from botocore.exceptions import NoCredentialsError, ClientError

# Import collectors
from collectors.iam import collect_iam_evidence
from collectors.s3 import collect_s3_evidence
from collectors.cloudtrail import collect_cloudtrail_evidence
from collectors.config import collect_config_evidence

# Import reporters
from reporters.excel import generate_excel_report
from reporters.manifest import write_manifest


# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# Tool version
TOOL_VERSION = "1.0.0"


def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """
    Load configuration from YAML file.

    Args:
        config_path: Path to config file

    Returns:
        Configuration dictionary
    """
    config_file = Path(config_path)

    if config_file.exists():
        with open(config_file, "r") as f:
            return yaml.safe_load(f) or {}

    # Return defaults if config doesn't exist
    return {
        "aws_profile": "default",
        "aws_region": "us-east-1",
        "output_directory": "./evidence-output",
        "inactive_credential_days": 90,
    }


def get_aws_account_id(profile_name: str, region: str) -> str:
    """
    Get the AWS account ID using STS.

    Args:
        profile_name: AWS profile name
        region: AWS region

    Returns:
        AWS account ID or "UNKNOWN"
    """
    try:
        session = boto3.Session(profile_name=profile_name)
        sts = session.client("sts", region_name=region)
        identity = sts.get_caller_identity()
        return identity.get("Account", "UNKNOWN")
    except Exception as e:
        logger.warning(f"Could not get AWS account ID: {e}")
        return "UNKNOWN"


def print_dry_run(
    profile_name: str,
    region: str,
    selected_collectors: List[str],
    config: Dict[str, Any],
) -> None:
    """
    Print what would be collected without making AWS calls.

    Args:
        profile_name: AWS profile name
        region: AWS region
        selected_collectors: List of collectors to run
        config: Configuration dictionary
    """
    print("\n" + "=" * 60)
    print("DRY RUN - No AWS calls will be made")
    print("=" * 60)
    print(f"\nConfiguration:")
    print(f"  AWS Profile: {profile_name}")
    print(f"  AWS Region: {region}")
    print(f"  Output Directory: {config.get('output_directory', './evidence-output')}")
    print(f"  Inactive Credential Days: {config.get('inactive_credential_days', 90)}")
    print(f"\nCollectors to run:")

    available_collectors = {
        "iam": "IAM evidence (MFA, password policy, unused credentials)",
        "s3": "S3 evidence (encryption, public access, bucket policies)",
        "cloudtrail": "CloudTrail evidence (logging, multi-region, validation)",
        "config": "AWS Config evidence (compliance rules)",
    }

    for collector in selected_collectors:
        description = available_collectors.get(collector, "Unknown collector")
        print(f"  - {collector}: {description}")

    print("\nChecks that will be performed:")
    checks = {
        "IAM": [
            "mfa_enabled - MFA status for all users",
            "password_policy_strength - Password policy requirements",
            "password_policy_expiry - Password expiration policy",
            "unused_credentials - Credentials unused >90 days",
            "root_account_mfa - Root account MFA status",
        ],
        "S3": [
            "s3_default_encryption - Default bucket encryption",
            "s3_public_access_block - Public access blocking",
            "s3_bucket_policy_exists - Explicit bucket policies",
            "s3_versioning_enabled - Versioning status",
            "s3_access_logging - Access logging configuration",
        ],
        "CloudTrail": [
            "cloudtrail_enabled - At least one trail exists",
            "cloudtrail_multi_region - Multi-region logging",
            "cloudtrail_log_validation - Log file integrity",
            "cloudtrail_encryption - KMS encryption at rest",
        ],
        "AWS Config": [
            "config_enabled - Config recorder active",
            "config_compliance_status - Compliance rules status",
        ],
    }

    for service, service_checks in checks.items():
        if any(s in selected_collectors for s in ["iam", "s3", "cloudtrail", "config"]):
            if (
                (service == "IAM" and "iam" in selected_collectors)
                or (service == "S3" and "s3" in selected_collectors)
                or (service == "CloudTrail" and "cloudtrail" in selected_collectors)
                or (service == "AWS Config" and "config" in selected_collectors)
            ):
                print(f"\n  {service}:")
                for check in service_checks:
                    print(f"    - {check}")

    print("\n" + "=" * 60)
    print("Output files that will be generated:")
    print("  - raw/iam.json")
    print("  - raw/s3.json")
    print("  - raw/cloudtrail.json")
    print("  - report.xlsx")
    print("  - manifest.json")
    print("=" * 60 + "\n")


def run_collection(
    profile_name: str,
    region: str,
    selected_collectors: List[str],
    output_dir: str,
    inactive_days: int,
) -> Dict[str, Any]:
    """
    Run the compliance evidence collection.

    Args:
        profile_name: AWS profile name
        region: AWS region
        selected_collectors: List of collectors to run
        output_dir: Output directory path
        inactive_days: Days to consider credentials as unused

    Returns:
        Dictionary containing all findings and raw data
    """
    all_findings: List[Dict[str, Any]] = []
    all_raw_data: Dict[str, Any] = {}

    logger.info(f"Starting compliance evidence collection...")
    logger.info(f"Profile: {profile_name}, Region: {region}")

    # Collect IAM evidence
    if "iam" in selected_collectors:
        logger.info("Collecting IAM evidence...")
        try:
            iam_result = collect_iam_evidence(profile_name, region, inactive_days)
            all_findings.extend(iam_result.get("findings", []))
            all_raw_data["iam"] = iam_result.get("raw_data", {})
            logger.info(f"IAM: {len(iam_result.get('findings', []))} findings")
        except Exception as e:
            logger.error(f"IAM collection failed: {e}")

    # Collect S3 evidence
    if "s3" in selected_collectors:
        logger.info("Collecting S3 evidence...")
        try:
            s3_result = collect_s3_evidence(profile_name, region)
            all_findings.extend(s3_result.get("findings", []))
            all_raw_data["s3"] = s3_result.get("raw_data", {})
            logger.info(f"S3: {len(s3_result.get('findings', []))} findings")
        except Exception as e:
            logger.error(f"S3 collection failed: {e}")

    # Collect CloudTrail evidence
    if "cloudtrail" in selected_collectors:
        logger.info("Collecting CloudTrail evidence...")
        try:
            cloudtrail_result = collect_cloudtrail_evidence(profile_name, region)
            all_findings.extend(cloudtrail_result.get("findings", []))
            all_raw_data["cloudtrail"] = cloudtrail_result.get("raw_data", {})
            logger.info(
                f"CloudTrail: {len(cloudtrail_result.get('findings', []))} findings"
            )
        except Exception as e:
            logger.error(f"CloudTrail collection failed: {e}")

    # Collect AWS Config evidence
    if "config" in selected_collectors:
        logger.info("Collecting AWS Config evidence...")
        try:
            config_result = collect_config_evidence(profile_name, region)
            all_findings.extend(config_result.get("findings", []))
            all_raw_data["config"] = config_result.get("raw_data", {})
            logger.info(
                f"AWS Config: {len(config_result.get('findings', []))} findings"
            )
        except Exception as e:
            logger.error(f"AWS Config collection failed: {e}")

    return {"findings": all_findings, "raw_data": all_raw_data}


def save_outputs(
    findings: List[Dict[str, Any]],
    raw_data: Dict[str, Any],
    output_dir: str,
    aws_account_id: str,
    region: str,
) -> None:
    """
    Save all output files.

    Args:
        findings: List of all findings
        raw_data: Raw API responses
        output_dir: Output directory
        aws_account_id: AWS account ID
        region: AWS region
    """
    # Create output directory structure
    output_path = Path(output_dir)
    raw_dir = output_path / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    # Save raw data files
    logger.info("Saving raw data files...")

    if "iam" in raw_data:
        with open(raw_dir / "iam.json", "w") as f:
            json.dump(raw_data["iam"], f, indent=2, default=str)

    if "s3" in raw_data:
        with open(raw_dir / "s3.json", "w") as f:
            json.dump(raw_data["s3"], f, indent=2, default=str)

    if "cloudtrail" in raw_data:
        with open(raw_dir / "cloudtrail.json", "w") as f:
            json.dump(raw_data["cloudtrail"], f, indent=2, default=str)

    # Generate manifest
    logger.info("Generating manifest...")
    write_manifest(
        findings,
        str(output_path / "manifest.json"),
        aws_account_id,
        region,
        TOOL_VERSION,
    )

    # Generate Excel report
    logger.info("Generating Excel report...")
    try:
        metadata = {
            "aws_account_id": aws_account_id,
            "region": region,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_version": TOOL_VERSION,
        }
        generate_excel_report(findings, str(output_path / "report.xlsx"), metadata)
    except ImportError:
        logger.warning("openpyxl not installed - skipping Excel report")
        logger.warning("Install with: pip install openpyxl")
    except Exception as e:
        logger.error(f"Failed to generate Excel report: {e}")

    # Print summary
    status_counts = {"PASS": 0, "FAIL": 0, "MANUAL_REVIEW": 0}
    for finding in findings:
        status = finding.get("status", "UNKNOWN")
        if status in status_counts:
            status_counts[status] += 1

    print("\n" + "=" * 60)
    print("EVIDENCE COLLECTION COMPLETE")
    print("=" * 60)
    print(f"\nOutput directory: {output_dir}")
    print(f"\nSummary:")
    print(f"  Total findings: {len(findings)}")
    print(f"  PASS: {status_counts['PASS']}")
    print(f"  FAIL: {status_counts['FAIL']}")
    print(f"  MANUAL_REVIEW: {status_counts['MANUAL_REVIEW']}")
    print(f"\nFiles generated:")
    print(f"  - raw/iam.json")
    print(f"  - raw/s3.json")
    print(f"  - raw/cloudtrail.json")
    print(f"  - report.xlsx")
    print(f"  - manifest.json")
    print("=" * 60 + "\n")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Compliance Harvester - Collect AWS evidence for SOC 2 and GDPR",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python collect.py --profile default --region us-east-1 --output ./output
  python collect.py --dry-run
  python collect.py --checks iam,s3
  python collect.py --config custom-config.yaml

Collectors:
  iam        - IAM evidence (MFA, password policy, unused credentials)
  s3         - S3 evidence (encryption, public access, bucket policies)
  cloudtrail - CloudTrail evidence (logging, multi-region, validation)
  config     - AWS Config evidence (compliance rules)
        """,
    )

    parser.add_argument(
        "--profile", default="default", help="AWS profile name (default: default)"
    )

    parser.add_argument(
        "--region", default="us-east-1", help="AWS region (default: us-east-1)"
    )

    parser.add_argument(
        "--output",
        default="./evidence-output",
        help="Output directory (default: ./evidence-output)",
    )

    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Config file path (default: config.yaml)",
    )

    parser.add_argument(
        "--checks",
        default="iam,s3,cloudtrail,config",
        help="Comma-separated list of collectors to run (default: all)",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be collected without making AWS calls",
    )

    parser.add_argument(
        "--inactive-days",
        type=int,
        default=90,
        help="Days to consider credentials as unused (default: 90)",
    )

    parser.add_argument(
        "--version", action="version", version=f"Compliance Harvester v{TOOL_VERSION}"
    )

    args = parser.parse_args()

    # Parse selected collectors
    selected_collectors = [c.strip() for c in args.checks.split(",")]
    valid_collectors = {"iam", "s3", "cloudtrail", "config"}

    # Validate collectors
    invalid_collectors = set(selected_collectors) - valid_collectors
    if invalid_collectors:
        print(f"Error: Invalid collectors: {invalid_collectors}")
        print(f"Valid collectors: {', '.join(sorted(valid_collectors))}")
        sys.exit(1)

    # Load configuration
    config = load_config(args.config)

    # Handle dry-run mode
    if args.dry_run:
        print_dry_run(args.profile, args.region, selected_collectors, config)
        sys.exit(0)

    # Get AWS account ID
    aws_account_id = get_aws_account_id(args.profile, args.region)
    logger.info(f"AWS Account ID: {aws_account_id}")

    # Run evidence collection
    result = run_collection(
        args.profile, args.region, selected_collectors, args.output, args.inactive_days
    )

    # Save outputs
    save_outputs(
        result["findings"], result["raw_data"], args.output, aws_account_id, args.region
    )


if __name__ == "__main__":
    main()
