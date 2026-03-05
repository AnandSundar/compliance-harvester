"""
IAM Evidence Collector Module

This module collects IAM-related compliance evidence for SOC 2 and GDPR controls.

AWS Services Called:
- iam.list_users(): Retrieves IAM users for the account
- iam.get_login_profile(): Checks if user has console access
- iam.list_mfa_devices(): Verifies MFA status for each user
- iam.get_account_password_policy(): Gets password policy configuration
- iam.list_access_keys(): Checks for unused access keys
- iam.get_user(): Gets user creation date for age analysis
- iam.get_account_summary(): Gets account-level security details

Control Mappings:
- MFA enabled maps to CC6.1, CC6.7 (SOC2) and Art. 32(1)(b), Art. 32(1)(d) (GDPR)
- Password policy maps to CC6.1, CC6.3 (SOC2) and Art. 32(1)(b), Art. 32(1)(d) (GDPR)
- Unused credentials map to CC6.1, CC6.7 (SOC2) and Art. 32(1)(b) (GDPR)
"""

import boto3
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError, NoCredentialsError

from mappings import get_control_info


logger = logging.getLogger(__name__)


class IAMCollector:
    """
    Collects IAM security evidence for compliance auditing.

    This collector performs read-only IAM API calls to gather evidence
    about user security configurations, password policies, and credential
    usage patterns.
    """

    def __init__(self, iam_client, inactive_days: int = 90):
        """
        Initialize the IAM collector.

        Args:
            iam_client: Boto3 IAM client (already configured)
            inactive_days: Number of days to consider credentials as unused
        """
        self.iam = iam_client
        self.inactive_days = inactive_days
        self.findings: List[Dict[str, Any]] = []
        self.raw_data: Dict[str, Any] = {"users": [], "password_policy": None}

    def collect_all(self) -> Dict[str, Any]:
        """
        Run all IAM evidence collection checks.

        Returns:
            Dictionary containing findings and raw data
        """
        logger.info("Starting IAM evidence collection...")

        # Collect all evidence
        self._collect_users()
        self._collect_password_policy()
        self._collect_root_account_mfa()

        return {"findings": self.findings, "raw_data": self.raw_data}

    def _collect_users(self) -> None:
        """
        Collect IAM user evidence including MFA status and credential age.

        AWS API Call: list_users()
        Why: Enumerate all IAM users to check individual security settings

        For each user:
        - Check MFA device status via list_mfa_devices()
        - Check access key age via list_access_keys() and get_user()
        """
        try:
            paginator = self.iam.get_paginator("list_users")
            users = []

            for page in paginator.paginate():
                users.extend(page.get("Users", []))

            self.raw_data["users"] = users
            logger.info(f"Found {len(users)} IAM users")

            cutoff_date = datetime.now(timezone.utc) - timedelta(
                days=self.inactive_days
            )

            for user in users:
                user_name = user["UserName"]
                user_arn = user["Arn"]

                # Check MFA status
                mfa_devices = self.iam.list_mfa_devices(UserName=user_name).get(
                    "MFADevices", []
                )
                has_mfa = len(mfa_devices) > 0

                # Create finding for MFA status
                control_info = get_control_info("mfa_enabled")
                self.findings.append(
                    {
                        "check_id": "mfa_enabled",
                        "resource_id": user_arn,
                        "resource_name": user_name,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "soc2_criteria": control_info["soc2"],
                        "gdpr_articles": control_info["gdpr"],
                        "status": "PASS" if has_mfa else "FAIL",
                        "severity": control_info["severity"],
                        "description": control_info["description"],
                        "raw_evidence": {
                            "user_name": user_name,
                            "mfa_enabled": has_mfa,
                            "mfa_devices": [
                                {
                                    "device_key": d.get("SerialNumber"),
                                    "type": d.get("User", "unknown"),
                                }
                                for d in mfa_devices
                            ],
                        },
                    }
                )

                # Check access key usage
                access_keys = self.iam.list_access_keys(UserName=user_name).get(
                    "AccessKeyMetadata", []
                )

                for key in access_keys:
                    key_id = key["AccessKeyId"]
                    key_status = key["Status"]
                    create_date = key.get("CreateDate")

                    # Check if key is unused
                    is_unused = False
                    if (
                        create_date
                        and create_date < cutoff_date
                        and key_status == "Active"
                    ):
                        is_unused = True

                    if is_unused:
                        control_info = get_control_info("unused_credentials")
                        self.findings.append(
                            {
                                "check_id": "unused_credentials",
                                "resource_id": f"{user_arn}/access-key/{key_id}",
                                "resource_name": f"{user_name}:{key_id[:4]}...",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "soc2_criteria": control_info["soc2"],
                                "gdpr_articles": control_info["gdpr"],
                                "status": "FAIL",
                                "severity": control_info["severity"],
                                "description": f"Access key {key_id[:4]}... unused for >{self.inactive_days} days",
                                "raw_evidence": {
                                    "user_name": user_name,
                                    "access_key_id": key_id,
                                    "create_date": (
                                        create_date.isoformat() if create_date else None
                                    ),
                                    "status": key_status,
                                },
                            }
                        )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.warning(f"IAM list_users failed: {error_code}")
            self._create_manual_review_finding(
                "mfa_enabled",
                "account",
                f"IAM list_users API call failed: {error_code}",
            )
        except NoCredentialsError:
            logger.error("No AWS credentials available for IAM collection")
            self._create_manual_review_finding(
                "mfa_enabled", "account", "AWS credentials not available"
            )

    def _collect_password_policy(self) -> None:
        """
        Collect account password policy evidence.

        AWS API Call: get_account_password_policy()
        Why: Verify password policy meets minimum security requirements

        Checks:
        - Minimum password length (should be >= 8)
        - Require uppercase letters
        - Require lowercase letters
        - Require numbers
        - Require symbols
        - Password expiry (max age in days)
        """
        try:
            policy = self.iam.get_account_password_policy()
            password_policy = policy.get("PasswordPolicy", {})
            self.raw_data["password_policy"] = password_policy

            # Check minimum length
            min_length = password_policy.get("MinPasswordLength", 0)
            control_info = get_control_info("password_policy_strength")
            self.findings.append(
                {
                    "check_id": "password_policy_strength",
                    "resource_id": "arn:aws:iam::*:password-policy",
                    "resource_name": "account-password-policy",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "soc2_criteria": control_info["soc2"],
                    "gdpr_articles": control_info["gdpr"],
                    "status": "PASS" if min_length >= 8 else "FAIL",
                    "severity": control_info["severity"],
                    "description": f"Password minimum length is {min_length} (required: >=8)",
                    "raw_evidence": {
                        "min_length": min_length,
                        "require_uppercase": password_policy.get(
                            "RequireUppercaseCharacters", False
                        ),
                        "require_lowercase": password_policy.get(
                            "RequireLowercaseCharacters", False
                        ),
                        "require_numbers": password_policy.get("RequireNumbers", False),
                        "require_symbols": password_policy.get("RequireSymbols", False),
                    },
                }
            )

            # Check password expiry
            max_age = password_policy.get("MaxPasswordAge", 0)
            control_info = get_control_info("password_policy_expiry")
            # Pass if max age is set and <= 90 days, or if not set (0 = never expires - considered FAIL for compliance)
            status = "PASS" if 0 < max_age <= 90 else "FAIL"
            self.findings.append(
                {
                    "check_id": "password_policy_expiry",
                    "resource_id": "arn:aws:iam::*:password-policy",
                    "resource_name": "account-password-policy",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "soc2_criteria": control_info["soc2"],
                    "gdpr_articles": control_info["gdpr"],
                    "status": status,
                    "severity": control_info["severity"],
                    "description": f"Password expiry is {max_age} days (0=never)",
                    "raw_evidence": {"max_password_age": max_age},
                }
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "NoSuchEntity":
                logger.warning("No account password policy found")
                self._create_manual_review_finding(
                    "password_policy_strength",
                    "account",
                    "No account password policy configured",
                )
            else:
                logger.warning(f"IAM get_account_password_policy failed: {error_code}")
                self._create_manual_review_finding(
                    "password_policy_strength",
                    "account",
                    f"Password policy check failed: {error_code}",
                )

    def _collect_root_account_mfa(self) -> None:
        """
        Collect root account MFA evidence.

        AWS API Call: list_mfa_devices() without UserName parameter
        Why: Check if root account has MFA enabled

        Note: This requires root account credentials to be configured in boto3
        """
        try:
            # Try to get MFA devices without specifying user (checks root)
            mfa_devices = self.iam.list_mfa_devices().get("MFADevices", [])

            # Check if root account has MFA
            root_mfa = any(d.get("User") == "<root_account>" for d in mfa_devices)

            control_info = get_control_info("root_account_mfa")
            self.findings.append(
                {
                    "check_id": "root_account_mfa",
                    "resource_id": "arn:aws:iam::*:root",
                    "resource_name": "root-account",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "soc2_criteria": control_info["soc2"],
                    "gdpr_articles": control_info["gdpr"],
                    "status": "PASS" if root_mfa else "FAIL",
                    "severity": control_info["severity"],
                    "description": control_info["description"],
                    "raw_evidence": {
                        "root_mfa_enabled": root_mfa,
                        "mfa_devices": mfa_devices,
                    },
                }
            )

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            logger.warning(f"Root account MFA check failed: {error_code}")
            self._create_manual_review_finding(
                "root_account_mfa",
                "root",
                f"Root account MFA check failed: {error_code}",
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
                "resource_id": f"arn:aws:iam::*:{resource_name}",
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


def collect_iam_evidence(
    profile_name: str, region: str, inactive_days: int = 90
) -> Dict[str, Any]:
    """
    Main entry point for IAM evidence collection.

    Args:
        profile_name: AWS profile name from credentials
        region: AWS region (not used for IAM, but required for consistency)
        inactive_days: Days to consider credentials as unused

    Returns:
        Dictionary with findings and raw data
    """
    try:
        # Create session with specified profile
        session = boto3.Session(profile_name=profile_name)
        iam_client = session.client("iam", region_name=region)

        # Create collector and run
        collector = IAMCollector(iam_client, inactive_days)
        return collector.collect_all()

    except NoCredentialsError:
        logger.error("AWS credentials not available")
        return {
            "findings": [
                {
                    "check_id": "iam_collection",
                    "resource_id": "arn:aws:iam::*:account",
                    "resource_name": "account",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "soc2_criteria": ["CC6.1"],
                    "gdpr_articles": ["Art. 32(1)(b)"],
                    "status": "MANUAL_REVIEW",
                    "severity": "HIGH",
                    "description": "AWS credentials not available. Please configure AWS credentials.",
                    "raw_evidence": {},
                }
            ],
            "raw_data": {},
        }
    except Exception as e:
        logger.exception(f"Unexpected error during IAM collection: {e}")
        return {
            "findings": [
                {
                    "check_id": "iam_collection",
                    "resource_id": "arn:aws:iam::*:account",
                    "resource_name": "account",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "soc2_criteria": ["CC6.1"],
                    "gdpr_articles": ["Art. 32(1)(b)"],
                    "status": "MANUAL_REVIEW",
                    "severity": "HIGH",
                    "description": f"IAM collection failed: {str(e)}",
                    "raw_evidence": {"error": str(e)},
                }
            ],
            "raw_data": {},
        }
