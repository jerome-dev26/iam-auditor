import argparse
import logging
import os
import boto3
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Audit IAM users for MFA gaps, stale keys, and admin policies."
    )
    parser.add_argument(
        "--key-age-threshold",
        type=int,
        default=int(os.getenv("KEY_AGE_THRESHOLD", 90)),
        help="Flag access keys older than this many days (default: from .env or 90)"
    )
    parser.add_argument(
        "--output",
        choices=["json", "summary"],
        default="summary",
        help="Output format (default: summary)"
    )
    parser.add_argument(
        "--profile",
        default=os.getenv("AWS_PROFILE"),
        help="AWS CLI profile to use (default: from .env or environment credentials)"
    )
    return parser.parse_args()

def check_mfa(iam_client, username):
    """Return True if the user has no MFA device registered."""
    mfa_devices = iam_client.list_mfa_devices(UserName=username)["MFADevices"]
    return len(mfa_devices) == 0


def check_stale_keys(iam_client, username, threshold_days):
    """Return a list of active access key ages (in days) that exceed the threshold."""
    stale = []
    keys = iam_client.list_access_keys(UserName=username)["AccessKeyMetadata"]
    for key in keys:
        if key["Status"] == "Active":
            age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days
            if age_days > threshold_days:
                stale.append(age_days)
    return stale


def check_admin_policies(iam_client, username):
    """Return a list of attached policy names that look admin-level."""
    admin_policies = []
    attached = iam_client.list_attached_user_policies(UserName=username)["AttachedPolicies"]
    for policy in attached:
        if "Admin" in policy["PolicyName"] or policy["PolicyArn"].endswith("/AdministratorAccess"):
            admin_policies.append(policy["PolicyName"])
    return admin_policies

def audit_iam_users(iam_client, key_age_threshold):
    """Run all checks against every IAM user and return a list of findings."""
    findings = []
    paginator = iam_client.get_paginator("list_users")

    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            logger.debug("Auditing user: %s", username)

            user_findings = {"user": username, "issues": []}

            if check_mfa(iam_client, username):
                user_findings["issues"].append("no_mfa")
                logger.debug("%s: no MFA device found", username)

            stale_keys = check_stale_keys(iam_client, username, key_age_threshold)
            for age in stale_keys:
                user_findings["issues"].append(f"key_age_{age}_days")
                logger.debug("%s: active key %d days old", username, age)

            admin_policies = check_admin_policies(iam_client, username)
            for policy_name in admin_policies:
                user_findings["issues"].append(f"admin_policy_{policy_name}")
                logger.debug("%s: admin policy attached (%s)", username, policy_name)

            if user_findings["issues"]:
                findings.append(user_findings)

    logger.info("Audit complete: %d users with issues out of scan", len(findings))
    return findings

def main():
    args = parse_args()
    logger.info("Starting IAM audit with key age threshold=%d days, output=%s, profile=%s",
                args.key_age_threshold, args.output, args.profile or "default")

    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    iam_client = session.client("iam")

    results = audit_iam_users(iam_client, args.key_age_threshold)

    if args.output == "json":
        import json
        print(json.dumps(results, indent=2))
    else:
        if not results:
            print("No issues found.")
        for entry in results:
            print(f"User: {entry['user']}")
            for issue in entry["issues"]:
                print(f"  - {issue}")

if __name__ == "__main__":
    main()