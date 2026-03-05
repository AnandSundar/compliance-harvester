"""
AWS Config Evidence Collector Module

This module collects AWS Config compliance evidence for SOC 2 and GDPR controls.

AWS Services Called:
- config.describe_configuration_recorders(): Gets Config recorder status
- config.describe_delivery_channels(): Gets delivery channel configuration
- config.describe_config_rules(): Lists all Config rules
- config.get_compliance_summary_by_config_rule(): Gets compliance summary
- config.get_compliance_details_by_config_rule(): Gets detailed compliance

Control Mappings:
- Config enabled maps to CC7.2, CC7.3 (SOC2) and Art. 32(1)(d) (GDPR)
- Config compliance status maps to CC7.2, CC7.3, CC7.4 (SOC2) and Art. 32(1)(d) (GDPR)

Note: AWS Config is optional. If not enabled, this collector gracefully skips
with MANUAL_REVIEW findings rather than failing.
"""

import boto3
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any
from botocore.exceptions import ClientError, NoCredentialsError

from mappings import get_control_info


logger = logging.getLogger(__name__)


class ConfigCollector:
    """
    Collects AWS Config compliance evidence for compliance auditing.

    This collector performs read-only AWS Config API calls to gather evidence
    about configuration monitoring and compliance status. It gracefully handles
    cases where AWS Config is not enabled.
    """

    def __init__(self, config_client):
        """
        Initialize the AWS Config collector.

        Args:
            config_client: Boto3 Config client
        """
        self.config = config_client
        self.findings: List[Dict[str, Any]] = []
        self.raw_data: Dict[str, Any] = {
            "recorders": [],
            "delivery_channels": [],
            "rules": [],
            "compliance": {},
        }

    def collect_all(self) -> Dict[str, Any]:
        """
        Run all AWS Config evidence collection checks.

        Returns:
            Dictionary containing findings and raw data
        """
        logger.info("Starting AWS Config evidence collection...")

        # Collect all evidence
        self._collect_config_recorders()
        self._collect_delivery_channels()
        self._collect_config_rules()

        return {"findings": self.findings, "raw_data": self.raw_data}

    def _collect_config_recorders(self) -> None:
        """
        Collect AWS Config recorder status.

        AWS API Call: describe_configuration_recorders()
        Why: Verify AWS Config is enabled and recording resources
        """
        try:
            response = self.config.describe_configuration_recorders()
            recorders = response.get("ConfigurationRecorders", [])

            self.raw_data["recorders"] = [
                {
                    "name": r.get("name"),
                    "role_arn": r.get("roleARN"),
                    "recording_group": r.get("recordingGroup"),
                }
                for r in recorders
            ]

            logger.info(f"Found {len(recorders)} Config recorders")

            # Check if at least one recorder is enabled
            has_recorder = len(recorders) > 0
            is_recording = any(
                r.get("recordingGroup", {}).get("allSupported", False)
                or r.get("recordingGroup", {}).get("resourceTypes")
                for r in recorders
            )

            control_info = get_control_info("config_enabled")
            self.findings.append(
                {
                    "check_id": "config_enabled",
                    "resource_id": "arn:aws:config:::account",
                    "resource_name": "account",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "soc2_criteria": control_info["soc2"],
                    "gdpr_articles": control_info["gdpr"],
                    "status": (
                        "PASS" if (has_recorder and is_recording) else "MANUAL_REVIEW"
                    ),
                    "severity": control_info["severity"],
                    "description": "AWS Config recording status",
                    "raw_evidence": {
                        "recorders_count": len(recorders),
                        "is_recording": is_recording,
                    },
                }
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "NoSuchConfigurationRecorderException":
                logger.info("AWS Config is not enabled")
                self._create_config_not_enabled_finding()
            else:
                logger.warning(
                    f"Config describe_configuration_recorders failed: {error_code}"
                )
                self._create_manual_review_finding(
                    "config_enabled",
                    "account",
                    f"Failed to describe configuration recorders: {error_code}",
                )
        except NoCredentialsError:
            logger.error("No AWS credentials available for Config collection")
            self._create_manual_review_finding(
                "config_enabled", "account", "AWS credentials not available"
            )

    def _collect_delivery_channels(self) -> None:
        """
        Collect delivery channel configuration.

        AWS API Call: describe_delivery_channels()
        Why: Verify Config has a delivery channel configured
        """
        try:
            response = self.config.describe_delivery_channels()
            channels = response.get("DeliveryChannels", [])

            self.raw_data["delivery_channels"] = [
                {
                    "name": c.get("name"),
                    "s3_bucket_name": c.get("s3BucketName"),
                    "s3_key_prefix": c.get("s3KeyPrefix"),
                    "sns_topic_arn": c.get("snsTopicARN"),
                }
                for c in channels
            ]

            logger.info(f"Found {len(channels)} Config delivery channels")

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code != "NoSuchDeliveryChannelException":
                logger.warning(
                    f"Config describe_delivery_channels failed: {error_code}"
                )

    def _collect_config_rules(self) -> None:
        """
        Collect AWS Config rules and compliance status.

        AWS API Calls:
        - describe_config_rules(): List all rules
        - get_compliance_summary_by_config_rule(): Get compliance counts

        Why: Verify compliance monitoring is active
        """
        try:
            # Get all Config rules
            response = self.config.describe_config_rules()
            rules = response.get("ConfigRules", [])

            self.raw_data["rules"] = [
                {
                    "name": r.get("ConfigRuleName"),
                    "arn": r.get("ConfigRuleArn"),
                    "enabled": r.get("ConfigRuleState") == "ACTIVE",
                    "source": r.get("Source", {}).get("SourceIdentifier"),
                }
                for r in rules
            ]

            logger.info(f"Found {len(rules)} Config rules")

            # Get compliance summary
            try:
                compliance_response = (
                    self.config.get_compliance_summary_by_config_rule()
                )
                compliance_summary = compliance_response.get(
                    "ComplianceSummaryByConfigRule", []
                )

                # Parse compliance
                compliant_count = 0
                non_compliant_count = 0

                for item in compliance_summary:
                    compliance_type = item.get("ComplianceType", "UNKNOWN")
                    if compliance_type == "COMPLIANT":
                        compliant_count += 1
                    elif compliance_type == "NON_COMPLIANT":
                        non_compliant_count += 1

                self.raw_data["compliance"] = {
                    "compliant": compliant_count,
                    "non_compliant": non_compliant_count,
                    "total_rules": len(rules),
                }

            except ClientError as e:
                # If we can't get compliance, just note it
                logger.warning(f"Could not get compliance summary: {e}")

            # Create compliance status finding
            control_info = get_control_info("config_compliance_status")
            self.findings.append(
                {
                    "check_id": "config_compliance_status",
                    "resource_id": "arn:aws:config:::account",
                    "resource_name": "account",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "soc2_criteria": control_info["soc2"],
                    "gdpr_articles": control_info["gdpr"],
                    "status": "PASS" if len(rules) > 0 else "MANUAL_REVIEW",
                    "severity": control_info["severity"],
                    "description": control_info["description"],
                    "raw_evidence": {
                        "rules_count": len(rules),
                        "compliance_summary": self.raw_data.get("compliance", {}),
                    },
                }
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "NoSuchConfigurationRecorderException":
                # Config not enabled - already handled
                pass
            else:
                logger.warning(f"Config describe_config_rules failed: {error_code}")
                self._create_manual_review_finding(
                    "config_compliance_status",
                    "account",
                    f"Failed to describe Config rules: {error_code}",
                )

    def _create_config_not_enabled_finding(self) -> None:
        """Create findings when AWS Config is not enabled."""
        control_info = get_control_info("config_enabled")
        self.findings.append(
            {
                "check_id": "config_enabled",
                "resource_id": "arn:aws:config:::account",
                "resource_name": "account",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "soc2_criteria": control_info["soc2"],
                "gdpr_articles": control_info["gdpr"],
                "status": "MANUAL_REVIEW",
                "severity": control_info["severity"],
                "description": "AWS Config is not enabled. Enable for continuous compliance monitoring.",
                "raw_evidence": {"config_enabled": False},
            }
        )

        control_info = get_control_info("config_compliance_status")
        self.findings.append(
            {
                "check_id": "config_compliance_status",
                "resource_id": "arn:aws:config:::account",
                "resource_name": "account",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "soc2_criteria": control_info["soc2"],
                "gdpr_articles": control_info["gdpr"],
                "status": "MANUAL_REVIEW",
                "severity": control_info["severity"],
                "description": "AWS Config rules not available - Config not enabled",
                "raw_evidence": {"config_enabled": False},
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
                "resource_id": f"arn:aws:config:::{resource_name}",
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


def collect_config_evidence(profile_name: str, region: str) -> Dict[str, Any]:
    """
    Main entry point for AWS Config evidence collection.

    Args:
        profile_name: AWS profile name from credentials
        region: AWS region for Config operations

    Returns:
        Dictionary with findings and raw data
    """
    try:
        # Create session with specified profile
        session = boto3.Session(profile_name=profile_name)
        config_client = session.client("config", region_name=region)

        # Create collector and run
        collector = ConfigCollector(config_client)
        return collector.collect_all()

    except NoCredentialsError:
        logger.error("AWS credentials not available")
        return {
            "findings": [
                {
                    "check_id": "config_collection",
                    "resource_id": "arn:aws:config:::account",
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
        logger.exception(f"Unexpected error during Config collection: {e}")
        return {
            "findings": [
                {
                    "check_id": "config_collection",
                    "resource_id": "arn:aws:config:::account",
                    "resource_name": "account",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "soc2_criteria": ["CC7.2"],
                    "gdpr_articles": ["Art. 32(1)(d)"],
                    "status": "MANUAL_REVIEW",
                    "severity": "HIGH",
                    "description": f"Config collection failed: {str(e)}",
                    "raw_evidence": {"error": str(e)},
                }
            ],
            "raw_data": {},
        }
