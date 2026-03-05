"""
S3 Evidence Collector Module

This module collects S3-related compliance evidence for SOC 2 and GDPR controls.

AWS Services Called:
- s3.list_buckets(): Lists all S3 buckets in the account
- s3.get_bucket_encryption(): Checks default encryption status
- s3.get_public_access_block(): Checks public access block configuration
- s3.get_bucket_policy(): Checks if bucket has explicit policy
- s3.get_bucket_versioning(): Checks versioning status
- s3.get_bucket_logging(): Checks access logging configuration
- s3.get_bucket_location(): Gets bucket region

Control Mappings:
- Default encryption maps to CC6.7, CC6.8 (SOC2) and Art. 32(1)(a) (GDPR)
- Public access block maps to CC6.1, CC6.7 (SOC2) and Art. 32(1)(b) (GDPR)
- Bucket policy maps to CC6.1, CC6.7 (SOC2) and Art. 32(1)(b) (GDPR)
- Versioning maps to CC6.7, CC6.8 (SOC2) and Art. 32(1)(c) (GDPR)
- Access logging maps to CC7.2, CC7.3 (SOC2) and Art. 32(1)(d) (GDPR)
"""

import boto3
import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any
from botocore.exceptions import ClientError, NoCredentialsError

from mappings import get_control_info


logger = logging.getLogger(__name__)


class S3Collector:
    """
    Collects S3 bucket security evidence for compliance auditing.

    This collector performs read-only S3 API calls to gather evidence
    about bucket configurations, encryption settings, and access controls.
    """

    def __init__(self, s3_client, s3_control_client=None):
        """
        Initialize the S3 collector.

        Args:
            s3_client: Boto3 S3 client (for bucket operations)
            s3_control_client: Boto3 S3 Control client (for public access blocks)
        """
        self.s3 = s3_client
        self.s3_control = s3_control_client
        self.findings: List[Dict[str, Any]] = []
        self.raw_data: Dict[str, Any] = {"buckets": []}

    def collect_all(self) -> Dict[str, Any]:
        """
        Run all S3 evidence collection checks.

        Returns:
            Dictionary containing findings and raw data
        """
        logger.info("Starting S3 evidence collection...")

        # Collect all evidence
        self._collect_buckets()

        return {"findings": self.findings, "raw_data": self.raw_data}

    def _collect_buckets(self) -> None:
        """
        Collect evidence for all S3 buckets.

        AWS API Calls:
        - list_buckets(): Enumerate all buckets
        - get_bucket_encryption(): Check default encryption
        - get_public_access_block(): Check public access settings
        - get_bucket_policy(): Check explicit policy
        - get_bucket_versioning(): Check versioning
        - get_bucket_logging(): Check access logging
        """
        try:
            response = self.s3.list_buckets()
            buckets = response.get("Buckets", [])

            self.raw_data["buckets"] = [
                {
                    "name": b["Name"],
                    "creation_date": (
                        b["CreationDate"].isoformat() if b.get("CreationDate") else None
                    ),
                }
                for b in buckets
            ]

            logger.info(f"Found {len(buckets)} S3 buckets")

            for bucket in buckets:
                bucket_name = bucket["Name"]
                self._check_bucket_encryption(bucket_name)
                self._check_public_access_block(bucket_name)
                self._check_bucket_policy(bucket_name)
                self._check_bucket_versioning(bucket_name)
                self._check_bucket_logging(bucket_name)

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.warning(f"S3 list_buckets failed: {error_code}")
            self._create_manual_review_finding(
                "s3_default_encryption",
                "all-buckets",
                f"S3 list_buckets API call failed: {error_code}",
            )
        except NoCredentialsError:
            logger.error("No AWS credentials available for S3 collection")
            self._create_manual_review_finding(
                "s3_default_encryption", "account", "AWS credentials not available"
            )

    def _check_bucket_encryption(self, bucket_name: str) -> None:
        """
        Check if bucket has default encryption enabled.

        AWS API Call: get_bucket_encryption()
        Why: Verify data at rest is encrypted by default
        """
        try:
            response = self.s3.get_bucket_encryption(Bucket=bucket_name)
            server_side_encryption = response.get("ServerSideEncryptionRule", {})
            default_encryption = server_side_encryption.get(
                "ApplyServerSideEncryptionByDefault", {}
            )

            encryption_enabled = default_encryption.get("SSEAlgorithm") is not None

            control_info = get_control_info("s3_default_encryption")
            self.findings.append(
                {
                    "check_id": "s3_default_encryption",
                    "resource_id": f"arn:aws:s3:::{bucket_name}",
                    "resource_name": bucket_name,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "soc2_criteria": control_info["soc2"],
                    "gdpr_articles": control_info["gdpr"],
                    "status": "PASS" if encryption_enabled else "FAIL",
                    "severity": control_info["severity"],
                    "description": control_info["description"],
                    "raw_evidence": {
                        "bucket_name": bucket_name,
                        "encryption_enabled": encryption_enabled,
                        "algorithm": default_encryption.get("SSEAlgorithm", "None"),
                    },
                }
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                # No encryption configured - this is a FAIL
                control_info = get_control_info("s3_default_encryption")
                self.findings.append(
                    {
                        "check_id": "s3_default_encryption",
                        "resource_id": f"arn:aws:s3:::{bucket_name}",
                        "resource_name": bucket_name,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "soc2_criteria": control_info["soc2"],
                        "gdpr_articles": control_info["gdpr"],
                        "status": "FAIL",
                        "severity": control_info["severity"],
                        "description": "No default encryption configured on bucket",
                        "raw_evidence": {
                            "bucket_name": bucket_name,
                            "encryption_enabled": False,
                        },
                    }
                )
            else:
                logger.warning(
                    f"Failed to check encryption for {bucket_name}: {error_code}"
                )

    def _check_public_access_block(self, bucket_name: str) -> None:
        """
        Check if bucket has public access block enabled.

        AWS API Call: get_public_access_block()
        Why: Verify bucket is protected from public access
        """
        try:
            response = self.s3.get_public_access_block(Bucket=bucket_name)
            public_access_block = response.get("PublicAccessBlockConfiguration", {})

            # Check all public access block settings
            block_public_acls = public_access_block.get("BlockPublicAcls", False)
            block_public_policy = public_access_block.get("BlockPublicPolicy", False)
            ignore_public_acls = public_access_block.get("IgnorePublicAcls", False)
            restrict_public_buckets = public_access_block.get(
                "RestrictPublicBuckets", False
            )

            all_blocked = all(
                [
                    block_public_acls,
                    block_public_policy,
                    ignore_public_acls,
                    restrict_public_buckets,
                ]
            )

            control_info = get_control_info("s3_public_access_block")
            self.findings.append(
                {
                    "check_id": "s3_public_access_block",
                    "resource_id": f"arn:aws:s3:::{bucket_name}",
                    "resource_name": bucket_name,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "soc2_criteria": control_info["soc2"],
                    "gdpr_articles": control_info["gdpr"],
                    "status": "PASS" if all_blocked else "FAIL",
                    "severity": control_info["severity"],
                    "description": control_info["description"],
                    "raw_evidence": {
                        "bucket_name": bucket_name,
                        "block_public_acls": block_public_acls,
                        "block_public_policy": block_public_policy,
                        "ignore_public_acls": ignore_public_acls,
                        "restrict_public_buckets": restrict_public_buckets,
                    },
                }
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "NoSuchPublicAccessBlockConfiguration":
                # No public access block - this is a FAIL
                control_info = get_control_info("s3_public_access_block")
                self.findings.append(
                    {
                        "check_id": "s3_public_access_block",
                        "resource_id": f"arn:aws:s3:::{bucket_name}",
                        "resource_name": bucket_name,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "soc2_criteria": control_info["soc2"],
                        "gdpr_articles": control_info["gdpr"],
                        "status": "FAIL",
                        "severity": control_info["severity"],
                        "description": "No public access block configuration on bucket",
                        "raw_evidence": {
                            "bucket_name": bucket_name,
                            "public_access_block_enabled": False,
                        },
                    }
                )
            else:
                logger.warning(
                    f"Failed to check public access for {bucket_name}: {error_code}"
                )

    def _check_bucket_policy(self, bucket_name: str) -> None:
        """
        Check if bucket has an explicit policy.

        AWS API Call: get_bucket_policy()
        Why: Verify bucket has explicit access controls defined
        """
        try:
            response = self.s3.get_bucket_policy(Bucket=bucket_name)
            policy = response.get("Policy", "{}")

            # Parse the policy to check if it's not empty
            try:
                policy_json = json.loads(policy)
                policy_exists = bool(policy_json.get("Statement", []))
            except json.JSONDecodeError:
                policy_exists = False

            control_info = get_control_info("s3_bucket_policy_exists")
            self.findings.append(
                {
                    "check_id": "s3_bucket_policy_exists",
                    "resource_id": f"arn:aws:s3:::{bucket_name}",
                    "resource_name": bucket_name,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "soc2_criteria": control_info["soc2"],
                    "gdpr_articles": control_info["gdpr"],
                    "status": "PASS" if policy_exists else "MANUAL_REVIEW",
                    "severity": control_info["severity"],
                    "description": control_info["description"],
                    "raw_evidence": {
                        "bucket_name": bucket_name,
                        "policy_exists": policy_exists,
                    },
                }
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "NoSuchBucketPolicy":
                # No policy - this is a MANUAL_REVIEW (not necessarily a failure)
                control_info = get_control_info("s3_bucket_policy_exists")
                self.findings.append(
                    {
                        "check_id": "s3_bucket_policy_exists",
                        "resource_id": f"arn:aws:s3:::{bucket_name}",
                        "resource_name": bucket_name,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "soc2_criteria": control_info["soc2"],
                        "gdpr_articles": control_info["gdpr"],
                        "status": "MANUAL_REVIEW",
                        "severity": control_info["severity"],
                        "description": "No bucket policy - may be intentional for some use cases",
                        "raw_evidence": {
                            "bucket_name": bucket_name,
                            "policy_exists": False,
                        },
                    }
                )
            else:
                logger.warning(
                    f"Failed to check bucket policy for {bucket_name}: {error_code}"
                )

    def _check_bucket_versioning(self, bucket_name: str) -> None:
        """
        Check if bucket has versioning enabled.

        AWS API Call: get_bucket_versioning()
        Why: Verify data durability and recovery capability
        """
        try:
            response = self.s3.get_bucket_versioning(Bucket=bucket_name)
            status = response.get("Status", "Disabled")

            versioning_enabled = status == "Enabled"

            control_info = get_control_info("s3_versioning_enabled")
            self.findings.append(
                {
                    "check_id": "s3_versioning_enabled",
                    "resource_id": f"arn:aws:s3:::{bucket_name}",
                    "resource_name": bucket_name,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "soc2_criteria": control_info["soc2"],
                    "gdpr_articles": control_info["gdpr"],
                    "status": "PASS" if versioning_enabled else "MANUAL_REVIEW",
                    "severity": control_info["severity"],
                    "description": control_info["description"],
                    "raw_evidence": {
                        "bucket_name": bucket_name,
                        "versioning_enabled": versioning_enabled,
                        "status": status,
                    },
                }
            )

        except ClientError as e:
            logger.warning(f"Failed to check versioning for {bucket_name}")

    def _check_bucket_logging(self, bucket_name: str) -> None:
        """
        Check if bucket has access logging enabled.

        AWS API Call: get_bucket_logging()
        Why: Verify audit trail exists for access tracking
        """
        try:
            response = self.s3.get_bucket_logging(Bucket=bucket_name)
            logging_config = response.get("LoggingEnabled", {})

            logging_enabled = logging_config.get("TargetBucket") is not None

            control_info = get_control_info("s3_access_logging")
            self.findings.append(
                {
                    "check_id": "s3_access_logging",
                    "resource_id": f"arn:aws:s3:::{bucket_name}",
                    "resource_name": bucket_name,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "soc2_criteria": control_info["soc2"],
                    "gdpr_articles": control_info["gdpr"],
                    "status": "PASS" if logging_enabled else "MANUAL_REVIEW",
                    "severity": control_info["severity"],
                    "description": control_info["description"],
                    "raw_evidence": {
                        "bucket_name": bucket_name,
                        "logging_enabled": logging_enabled,
                        "target_bucket": logging_config.get("TargetBucket"),
                        "target_prefix": logging_config.get("TargetPrefix"),
                    },
                }
            )

        except ClientError as e:
            logger.warning(f"Failed to check logging for {bucket_name}")

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
                "resource_id": f"arn:aws:s3:::{resource_name}",
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


def collect_s3_evidence(profile_name: str, region: str) -> Dict[str, Any]:
    """
    Main entry point for S3 evidence collection.

    Args:
        profile_name: AWS profile name from credentials
        region: AWS region for S3 operations

    Returns:
        Dictionary with findings and raw data
    """
    try:
        # Create session with specified profile
        session = boto3.Session(profile_name=profile_name)
        s3_client = session.client("s3", region_name=region)

        # Create collector and run
        collector = S3Collector(s3_client)
        return collector.collect_all()

    except NoCredentialsError:
        logger.error("AWS credentials not available")
        return {
            "findings": [
                {
                    "check_id": "s3_collection",
                    "resource_id": "arn:aws:s3:::*",
                    "resource_name": "account",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "soc2_criteria": ["CC6.7"],
                    "gdpr_articles": ["Art. 32(1)(a)"],
                    "status": "MANUAL_REVIEW",
                    "severity": "HIGH",
                    "description": "AWS credentials not available. Please configure AWS credentials.",
                    "raw_evidence": {},
                }
            ],
            "raw_data": {},
        }
    except Exception as e:
        logger.exception(f"Unexpected error during S3 collection: {e}")
        return {
            "findings": [
                {
                    "check_id": "s3_collection",
                    "resource_id": "arn:aws:s3:::*",
                    "resource_name": "account",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "soc2_criteria": ["CC6.7"],
                    "gdpr_articles": ["Art. 32(1)(a)"],
                    "status": "MANUAL_REVIEW",
                    "severity": "HIGH",
                    "description": f"S3 collection failed: {str(e)}",
                    "raw_evidence": {"error": str(e)},
                }
            ],
            "raw_data": {},
        }
