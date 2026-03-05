"""
Control Mapping Module - SOC 2 Trust Service Criteria ↔ GDPR Article 32

This module contains the core control mapping that connects each evidence
check to its corresponding SOC 2 Trust Service Criteria and GDPR Article 32
sub-requirements.

The mapping serves as the "glue" between technical AWS configurations and
compliance requirements, enabling dual-audit evidence collection in a single run.

SOC 2 Trust Service Criteria (TSC) Categories:
- CC1: Control Environment
- CC2: Communication and Information
- CC3: Risk Assessment
- CC4: Monitoring Activities
- CC5: Control Activities
- CC6: Logical and Physical Access Controls
- CC7: System Operations
- CC8: Change Management
- CC9: Risk Mitigation

GDPR Article 32 relates to "Security of processing" and requires:
- Art. 32(1)(a): Pseudonymization and encryption of personal data
- Art. 32(1)(b): Ability to ensure confidentiality, integrity, availability
- Art. 32(1)(c): Ability to restore access to personal data
- Art. 32(1)(d): Regular testing of security measures
- Art. 32(2): Assessing appropriate technical measures considering state of art
"""

from typing import Dict, List, Any


# Core control mapping - each check maps to SOC2 criteria and GDPR articles
CONTROL_MAP: Dict[str, Dict[str, Any]] = {
    # ===========================================
    # IAM Controls
    # ===========================================
    "mfa_enabled": {
        "soc2": ["CC6.1", "CC6.7"],
        "gdpr": ["Art. 32(1)(b)", "Art. 32(1)(d)"],
        "description": "Multi-factor authentication is enabled for IAM users to prevent unauthorized access",
        "severity": "HIGH",
        "service": "IAM",
    },
    "password_policy_strength": {
        "soc2": ["CC6.1", "CC6.3"],
        "gdpr": ["Art. 32(1)(b)", "Art. 32(1)(d)"],
        "description": "Account password policy meets minimum strength requirements",
        "severity": "HIGH",
        "service": "IAM",
    },
    "password_policy_expiry": {
        "soc2": ["CC6.1", "CC6.3"],
        "gdpr": ["Art. 32(1)(b)", "Art. 32(1)(d)"],
        "description": "Passwords expire within acceptable timeframe to limit exposure window",
        "severity": "MEDIUM",
        "service": "IAM",
    },
    "unused_credentials": {
        "soc2": ["CC6.1", "CC6.7"],
        "gdpr": ["Art. 32(1)(b)"],
        "description": "IAM credentials unused for >90 days are identified for deactivation",
        "severity": "MEDIUM",
        "service": "IAM",
    },
    "root_account_mfa": {
        "soc2": ["CC6.1", "CC6.7"],
        "gdpr": ["Art. 32(1)(b)", "Art. 32(1)(d)"],
        "description": "Root account has MFA enabled for emergency access security",
        "severity": "HIGH",
        "service": "IAM",
    },
    # ===========================================
    # S3 Controls
    # ===========================================
    "s3_default_encryption": {
        "soc2": ["CC6.7", "CC6.8"],
        "gdpr": ["Art. 32(1)(a)"],
        "description": "S3 buckets have default encryption enabled to protect data at rest",
        "severity": "HIGH",
        "service": "S3",
    },
    "s3_public_access_block": {
        "soc2": ["CC6.1", "CC6.7"],
        "gdpr": ["Art. 32(1)(b)"],
        "description": "S3 buckets have public access blocks enabled to prevent data leakage",
        "severity": "HIGH",
        "service": "S3",
    },
    "s3_bucket_policy_exists": {
        "soc2": ["CC6.1", "CC6.7"],
        "gdpr": ["Art. 32(1)(b)"],
        "description": "S3 buckets have explicit policies defining access controls",
        "severity": "MEDIUM",
        "service": "S3",
    },
    "s3_versioning_enabled": {
        "soc2": ["CC6.7", "CC6.8"],
        "gdpr": ["Art. 32(1)(c)"],
        "description": "S3 versioning enabled for data durability and recovery capability",
        "severity": "MEDIUM",
        "service": "S3",
    },
    "s3_access_logging": {
        "soc2": ["CC7.2", "CC7.3"],
        "gdpr": ["Art. 32(1)(d)"],
        "description": "S3 access logging enabled for audit trail and anomaly detection",
        "severity": "MEDIUM",
        "service": "S3",
    },
    # ===========================================
    # CloudTrail Controls
    # ===========================================
    "cloudtrail_enabled": {
        "soc2": ["CC7.2", "CC7.3"],
        "gdpr": ["Art. 32(1)(d)", "Art. 32(1)(c)"],
        "description": "CloudTrail logging is enabled to track API activity",
        "severity": "HIGH",
        "service": "CloudTrail",
    },
    "cloudtrail_multi_region": {
        "soc2": ["CC7.2", "CC7.3"],
        "gdpr": ["Art. 32(1)(d)"],
        "description": "CloudTrail is configured for multi-region logging coverage",
        "severity": "HIGH",
        "service": "CloudTrail",
    },
    "cloudtrail_log_validation": {
        "soc2": ["CC7.2", "CC7.3", "CC7.4"],
        "gdpr": ["Art. 32(1)(c)", "Art. 32(1)(d)"],
        "description": "CloudTrail log file integrity validation is enabled",
        "severity": "HIGH",
        "service": "CloudTrail",
    },
    "cloudtrail_encrypted": {
        "soc2": ["CC6.7", "CC6.8"],
        "gdpr": ["Art. 32(1)(a)"],
        "description": "CloudTrail logs are encrypted at rest using KMS",
        "severity": "MEDIUM",
        "service": "CloudTrail",
    },
    # ===========================================
    # AWS Config Controls
    # ===========================================
    "config_enabled": {
        "soc2": ["CC7.2", "CC7.3"],
        "gdpr": ["Art. 32(1)(d)"],
        "description": "AWS Config is enabled for resource configuration tracking",
        "severity": "HIGH",
        "service": "Config",
    },
    "config_compliance_status": {
        "soc2": ["CC7.2", "CC7.3", "CC7.4"],
        "gdpr": ["Art. 32(1)(d)"],
        "description": "AWS Config rules compliance status for managed resources",
        "severity": "MEDIUM",
        "service": "Config",
    },
}


def get_control_info(check_id: str) -> Dict[str, Any]:
    """
    Retrieve control mapping information for a specific check.

    Args:
        check_id: The unique identifier for the check

    Returns:
        Dictionary containing SOC2 criteria, GDPR articles, description, and severity
    """
    return CONTROL_MAP.get(
        check_id,
        {
            "soc2": ["UNKNOWN"],
            "gdpr": ["UNKNOWN"],
            "description": "Unknown check - manual review required",
            "severity": "LOW",
            "service": "UNKNOWN",
        },
    )


def get_checks_by_service(service: str) -> List[str]:
    """
    Get all check IDs associated with a specific AWS service.

    Args:
        service: AWS service name (IAM, S3, CloudTrail, Config)

    Returns:
        List of check IDs for the service
    """
    return [
        check_id
        for check_id, info in CONTROL_MAP.items()
        if info.get("service", "").upper() == service.upper()
    ]


def get_all_checks() -> List[str]:
    """
    Get all available check IDs.

    Returns:
        List of all check IDs in the control map
    """
    return list(CONTROL_MAP.keys())


def get_severity_summary() -> Dict[str, int]:
    """
    Get a summary of checks grouped by severity.

    Returns:
        Dictionary with severity levels as keys and counts as values
    """
    summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for check_info in CONTROL_MAP.values():
        severity = check_info.get("severity", "LOW").upper()
        if severity in summary:
            summary[severity] += 1
    return summary
