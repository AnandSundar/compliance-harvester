"""
CloudTrail Evidence Collector Module

This module collects CloudTrail-related compliance evidence for SOC 2 and GDPR controls.

AWS Services Called:
- cloudtrail.describe_trails(): Lists all trails in the account
- cloudtrail.get_trail_status(): Gets status of each trail
- cloudtrail.get_event_selectors(): Gets event selector configuration
- cloudtrail.lookup_events(): (Optional) For recent event analysis

Control Mappings:
- CloudTrail enabled maps to CC7.2, CC7.3 (SOC2) and Art. 32(1)(d), Art. 32(1)(c) (GDPR)
- Multi-region logging maps to CC7.2, CC7.3 (SOC2) and Art. 32(1)(d) (GDPR)
- Log file validation maps to CC7.2, CC7.3, CC7.4 (SOC2) and Art. 32(1)(c), Art. 32(1)(d) (GDPR)
- Encrypted logs maps to CC6.7, CC6.8 (SOC2) and Art. 32(1)(a) (GDPR)
"""

import boto3
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any
from botocore.exceptions import ClientError, NoCredentialsError

from mappings import get_control_info


logger = logging.getLogger(__name__)


class CloudTrailCollector:
    """
    Collects CloudTrail logging evidence for compliance auditing.

    This collector performs read-only CloudTrail API calls to gather evidence
    about logging configuration, coverage, and integrity settings.
    """

    def __init__(self, cloudtrail_client):
        """
        Initialize the CloudTrail collector.

        Args:
            cloudtrail_client: Boto3 CloudTrail client
        """
        self.cloudtrail = cloudtrail_client
        self.findings: List[Dict[str, Any]] = []
        self.raw_data: Dict[str, Any] = {"trails": []}

    def collect_all(self) -> Dict[str, Any]:
        """
        Run all CloudTrail evidence collection checks.

        Returns:
            Dictionary containing findings and raw data
        """
        logger.info("Starting CloudTrail evidence collection...")

        # Collect all evidence
        self._collect_trails()

        return {"findings": self.findings, "raw_data": self.raw_data}

    def _collect_trails(self) -> None:
        """
        Collect evidence for all CloudTrail trails.

        AWS API Calls:
        - describe_trails(): Enumerate all trails
        - get_trail_status(): Get operational status
        - get_event_selectors(): Get event logging configuration
        """
        try:
            response = self.cloudtrail.describe_trails(includeShadowTrails=False)
            trails = response.get("trailList", [])

            self.raw_data["trails"] = [
                {
                    "name": t.get("Name"),
                    "s3_bucket_name": t.get("S3BucketName"),
                    "s3_key_prefix": t.get("S3KeyPrefix"),
                    "is_multi_region_trail": t.get("IsMultiRegionTrail", False),
                    "is_organization_trail": t.get("IsOrganizationTrail", False),
                    "log_file_validation_enabled": t.get(
                        "LogFileValidationEnabled", False
                    ),
                    "cloud_watch_logs_log_group_arn": t.get(
                        "CloudWatchLogsLogGroupArn"
                    ),
                    "kms_key_id": t.get("KmsKeyId"),
                }
                for t in trails
            ]

            logger.info(f"Found {len(trails)} CloudTrail trails")

            if not trails:
                # No trails configured - this is a critical failure
                self._create_no_trails_finding()
                return

            # Analyze each trail
            has_enabled_multi_region = False
            has_log_validation = False

            for trail in trails:
                trail_name = trail.get("Name")
                self._check_trail_status(trail_name)

                # Check multi-region
                is_multi_region = trail.get("IsMultiRegionTrail", False)
                if is_multi_region:
                    has_enabled_multi_region = True

                # Check log validation
                log_validation = trail.get("LogFileValidationEnabled", False)
                if log_validation:
                    has_log_validation = True

                # Check encryption
                self._check_trail_encryption(trail)

            # Create findings based on overall configuration
            self._create_trail_findings(
                trails_enabled=len(trails) > 0,
                multi_region=has_enabled_multi_region,
                log_validation=has_log_validation,
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.warning(f"CloudTrail describe_trails failed: {error_code}")
            self._create_manual_review_finding(
                "cloudtrail_enabled",
                "account",
                f"CloudTrail describe_trails API call failed: {error_code}",
            )
        except NoCredentialsError:
            logger.error("No AWS credentials available for CloudTrail collection")
            self._create_manual_review_finding(
                "cloudtrail_enabled", "account", "AWS credentials not available"
            )

    def _check_trail_status(self, trail_name: str) -> None:
        """
        Check if a specific trail is currently logging.

        AWS API Call: get_trail_status()
        Why: Verify trail is actively logging events
        """
        try:
            response = self.cloudtrail.get_trail_status(Name=trail_name)

            is_logging = response.get("IsLogging", False)

            # Store in raw data but don't create separate finding
            # The overall trail configuration is what matters
            for trail_data in self.raw_data["trails"]:
                if trail_data.get("name") == trail_name:
                    trail_data["is_logging"] = is_logging
                    trail_data["latest_delivery_time"] = response.get(
                        "LatestDeliveryTime"
                    )
                    trail_data["latest_delivery_error"] = response.get(
                        "LatestDeliveryError"
                    )

        except ClientError as e:
            logger.warning(f"Failed to get status for trail {trail_name}")

    def _check_trail_encryption(self, trail: Dict[str, Any]) -> None:
        """
        Check if trail logs are encrypted at rest.

        AWS API Call: Checks trail object for KmsKeyId
        Why: Verify log files are encrypted using KMS
        """
        kms_key_id = trail.get("KmsKeyId")
        encrypted = kms_key_id is not None

        control_info = get_control_info("cloudtrail_encrypted")
        self.findings.append(
            {
                "check_id": "cloudtrail_encrypted",
                "resource_id": f"arn:aws:cloudtrail:::trail/{trail.get('Name')}",
                "resource_name": trail.get("Name"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "soc2_criteria": control_info["soc2"],
                "gdpr_articles": control_info["gdpr"],
                "status": "PASS" if encrypted else "MANUAL_REVIEW",
                "severity": control_info["severity"],
                "description": control_info["description"],
                "raw_evidence": {
                    "trail_name": trail.get("Name"),
                    "encrypted": encrypted,
                    "kms_key_id": kms_key_id[:20] + "..." if kms_key_id else None,
                },
            }
        )

    def _create_no_trails_finding(self) -> None:
        """Create findings when no CloudTrail trails are configured."""
        control_info = get_control_info("cloudtrail_enabled")
        self.findings.append(
            {
                "check_id": "cloudtrail_enabled",
                "resource_id": "arn:aws:cloudtrail:::account",
                "resource_name": "account",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "soc2_criteria": control_info["soc2"],
                "gdpr_articles": control_info["gdpr"],
                "status": "FAIL",
                "severity": control_info["severity"],
                "description": "No CloudTrail trails configured in the account",
                "raw_evidence": {"trails_found": 0},
            }
        )

        # Also mark multi-region and validation as failed
        control_info = get_control_info("cloudtrail_multi_region")
        self.findings.append(
            {
                "check_id": "cloudtrail_multi_region",
                "resource_id": "arn:aws:cloudtrail:::account",
                "resource_name": "account",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "soc2_criteria": control_info["soc2"],
                "gdpr_articles": control_info["gdpr"],
                "status": "FAIL",
                "severity": control_info["severity"],
                "description": "Cannot verify - no CloudTrail configured",
                "raw_evidence": {"trails_found": 0},
            }
        )

        control_info = get_control_info("cloudtrail_log_validation")
        self.findings.append(
            {
                "check_id": "cloudtrail_log_validation",
                "resource_id": "arn:aws:cloudtrail:::account",
                "resource_name": "account",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "soc2_criteria": control_info["soc2"],
                "gdpr_articles": control_info["gdpr"],
                "status": "FAIL",
                "severity": control_info["severity"],
                "description": "Cannot verify - no CloudTrail configured",
                "raw_evidence": {"trails_found": 0},
            }
        )

    def _create_trail_findings(
        self, trails_enabled: bool, multi_region: bool, log_validation: bool
    ) -> None:
        """
        Create summary findings for trail configuration.

        Args:
            trails_enabled: Whether any trail is configured
            multi_region: Whether at least one trail is multi-region
            log_validation: Whether at least one trail has log validation
        """
        # CloudTrail enabled finding
        control_info = get_control_info("cloudtrail_enabled")
        self.findings.append(
            {
                "check_id": "cloudtrail_enabled",
                "resource_id": "arn:aws:cloudtrail:::account",
                "resource_name": "account",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "soc2_criteria": control_info["soc2"],
                "gdpr_articles": control_info["gdpr"],
                "status": "PASS" if trails_enabled else "FAIL",
                "severity": control_info["severity"],
                "description": control_info["description"],
                "raw_evidence": {"trails_configured": trails_enabled},
            }
        )

        # Multi-region finding
        control_info = get_control_info("cloudtrail_multi_region")
        self.findings.append(
            {
                "check_id": "cloudtrail_multi_region",
                "resource_id": "arn:aws:cloudtrail:::account",
                "resource_name": "account",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "soc2_criteria": control_info["soc2"],
                "gdpr_articles": control_info["gdpr"],
                "status": "PASS" if multi_region else "FAIL",
                "severity": control_info["severity"],
                "description": control_info["description"],
                "raw_evidence": {"multi_region_trail": multi_region},
            }
        )

        # Log validation finding
        control_info = get_control_info("cloudtrail_log_validation")
        self.findings.append(
            {
                "check_id": "cloudtrail_log_validation",
                "resource_id": "arn:aws:cloudtrail:::account",
                "resource_name": "account",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "soc2_criteria": control_info["soc2"],
                "gdpr_articles": control_info["gdpr"],
                "status": "PASS" if log_validation else "FAIL",
                "severity": control_info["severity"],
                "description": control_info["description"],
                "raw_evidence": {"log_validation_enabled": log_validation},
            }
        )

    def _create_manual_review_finding(
        self, check_id: str, resource_name: str, reason: str
    ) -> None:
        """
        Create a MANUAL_REVIEW finding when AWS API call fails.

        Args:
            check_id: The check that could not be performed
            resource_name: Name of the resource
            reason: Why the check requires manual review
        """
        control_info = get_control_info(check_id)
        self.findings.append(
            {
                "check_id": check_id,
                "resource_id": f"arn:aws:cloudtrail:::{resource_name}",
                "resource_name": resource_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "soc2_criteria": control_info["soc2"],
                "gdpr_articles": control_info["gdpr"],
                "status": "MANUAL_REVIEW",
                "severity": control_info["severity"],
                "description": f"Automated check failed: {reason}. Manual review required.",
                "raw_evidence": {"error": reason},
            }
        )


def collect_cloudtrail_evidence(profile_name: str, region: str) -> Dict[str, Any]:
    """
    Main entry point for CloudTrail evidence collection.

    Args:
        profile_name: AWS profile name from credentials
        region: AWS region for CloudTrail operations

    Returns:
        Dictionary with findings and raw data
    """
    try:
        # Create session with specified profile
        session = boto3.Session(profile_name=profile_name)
        cloudtrail_client = session.client("cloudtrail", region_name=region)

        # Create collector and run
        collector = CloudTrailCollector(cloudtrail_client)
        return collector.collect_all()

    except NoCredentialsError:
        logger.error("AWS credentials not available")
        return {
            "findings": [
                {
                    "check_id": "cloudtrail_collection",
                    "resource_id": "arn:aws:cloudtrail:::account",
                    "resource_name": "account",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "soc2_criteria": ["CC7.2"],
                    "gdpr_articles": ["Art. 32(1)(d)"],
                    "status": "MANUAL_REVIEW",
                    "severity": "HIGH",
                    "description": "AWS credentials not available. Please configure AWS credentials.",
                    "raw_evidence": {},
                }
            ],
            "raw_data": {},
        }
    except Exception as e:
        logger.exception(f"Unexpected error during CloudTrail collection: {e}")
        return {
            "findings": [
                {
                    "check_id": "cloudtrail_collection",
                    "resource_id": "arn:aws:cloudtrail:::account",
                    "resource_name": "account",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "soc2_criteria": ["CC7.2"],
                    "gdpr_articles": ["Art. 32(1)(d)"],
                    "status": "MANUAL_REVIEW",
                    "severity": "HIGH",
                    "description": f"CloudTrail collection failed: {str(e)}",
                    "raw_evidence": {"error": str(e)},
                }
            ],
            "raw_data": {},
        }
