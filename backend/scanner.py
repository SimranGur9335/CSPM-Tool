# scanner.py
# Simple rule-based scanner that inspects a JSON config and returns found issues.

from datetime import datetime

SEVERITY = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

def _issue(check_id, title, message, severity="MEDIUM", resource=None):
    return {
        "check_id": check_id,
        "title": title,
        "message": message,
        "severity": severity,
        "resource": resource
    }

def check_public_s3(cfg):
    issues = []
    for b in cfg.get("s3", []):
        # bucket may have `acl` or `policy` fields in our expected input format
        acl = (b.get("acl") or "").lower()
        policy = b.get("policy", "")
        if "public" in acl or "allusers" in policy.lower() or "authenticatedusers" in policy.lower():
            issues.append(_issue(
                "S3-001",
                "Public S3 bucket",
                f"Bucket '{b.get('name')}' appears public (acl='{acl}').",
                "HIGH",
                resource=b.get("name")
            ))
    return issues

def check_unencrypted_storage(cfg):
    issues = []
    # check S3
    for b in cfg.get("s3", []):
        enc = b.get("encryption", None)
        if enc is False or enc is None:
            issues.append(_issue("S3-002",
                                "Unencrypted storage",
                                f"S3 bucket '{b.get('name')}' has no encryption enabled.",
                                "MEDIUM",
                                resource=b.get("name")))
    # check RDS
    for r in cfg.get("rds_instances", []):
        if not r.get("storage_encrypted", False):
            issues.append(_issue("RDS-001",
                                "Unencrypted database storage",
                                f"RDS instance '{r.get('id')}' storage not encrypted.",
                                "HIGH",
                                resource=r.get("id")))
    return issues

def check_open_security_groups(cfg):
    issues = []
    for sg in cfg.get("security_groups", []):
        for rule in sg.get("inbound", []):
            cidr = rule.get("cidr") or rule.get("cidr_ip") or ""
            if cidr.strip() in ("0.0.0.0/0", "::/0"):
                issues.append(_issue("SG-001",
                                     "Open security group",
                                     f"Security group '{sg.get('id')}' has inbound {rule.get('port_description') or rule.get('port') } open to {cidr}.",
                                     "HIGH",
                                     resource=sg.get("id")))
    return issues

def check_unused_iam_keys(cfg):
    issues = []
    for u in cfg.get("iam_users", []):
        last_used_days = u.get("last_used_days")
        if last_used_days is not None and isinstance(last_used_days, (int, float)) and last_used_days > 90:
            issues.append(_issue("IAM-001",
                                 "Unused IAM user / access key",
                                 f"IAM user '{u.get('username')}' appears unused for {last_used_days} days.",
                                 "MEDIUM",
                                 resource=u.get("username")))
    return issues

def check_no_mfa(cfg):
    issues = []
    for u in cfg.get("iam_users", []):
        if not u.get("mfa_enabled", False):
            issues.append(_issue("IAM-002",
                                 "MFA not enabled",
                                 f"IAM user '{u.get('username')}' does not have MFA enabled.",
                                 "HIGH",
                                 resource=u.get("username")))
    return issues

def check_root_usage(cfg):
    issues = []
    root = cfg.get("root_account", {})
    # root may contain 'last_used_days' or 'used_recently' boolean
    last_used_days = root.get("last_used_days")
    if last_used_days is not None and last_used_days < 30:
        issues.append(_issue("ROOT-001",
                             "Root account used recently",
                             f"Root account used {last_used_days} days ago - consider using IAM instead.",
                             "CRITICAL",
                             resource="root"))
    return issues

def check_public_databases(cfg):
    issues = []
    for r in cfg.get("rds_instances", []):
        if r.get("publicly_accessible", False):
            issues.append(_issue("RDS-002",
                                 "Publicly accessible database",
                                 f"RDS instance '{r.get('id')}' is publicly accessible.",
                                 "CRITICAL",
                                 resource=r.get("id")))
    return issues

def check_cloudtrail(cfg):
    issues = []
    ct = cfg.get("cloudtrail", {})
    if not ct.get("enabled", False):
        issues.append(_issue("CT-001",
                             "CloudTrail disabled",
                             "CloudTrail (audit logs) appears disabled in this account.",
                             "HIGH",
                             resource=None))
    return issues

def check_default_vpc(cfg):
    issues = []
    default_vpcs = [v for v in cfg.get("vpcs", []) if v.get("is_default", False)]
    if default_vpcs:
        for v in default_vpcs:
            issues.append(_issue("VPC-001",
                                 "Default VPC in use",
                                 f"Default VPC '{v.get('id')}' exists - verify resource placement.",
                                 "LOW",
                                 resource=v.get("id")))
    return issues

def check_missing_backup(cfg):
    issues = []
    # Example: snap_count for volumes or a backups field
    if cfg.get("backups_enabled") is False:
        issues.append(_issue("BK-001",
                             "Backups disabled",
                             "Backups or snapshots are not enabled for resources.",
                             "HIGH",
                             resource=None))
    # check RDS snapshots
    for r in cfg.get("rds_instances", []):
        if not r.get("has_snapshot", False):
            issues.append(_issue("BK-002",
                                 "RDS snapshot missing",
                                 f"RDS instance '{r.get('id')}' has no recent snapshot.",
                                 "MEDIUM",
                                 resource=r.get("id")))
    return issues

def scan_config(config_json):
    """
    Main scanner entry. Accepts a parsed JSON/dict and returns:
      {
        "issues": [..],
        "summary": { "total": X, "by_severity": {...} }
      }
    """
    issues = []
    # safe calls: if keys missing, functions handle gracefully
    issues += check_public_s3(config_json)
    issues += check_unencrypted_storage(config_json)
    issues += check_open_security_groups(config_json)
    issues += check_unused_iam_keys(config_json)
    issues += check_no_mfa(config_json)
    issues += check_root_usage(config_json)
    issues += check_public_databases(config_json)
    issues += check_cloudtrail(config_json)
    issues += check_default_vpc(config_json)
    issues += check_missing_backup(config_json)

    # build summary
    totals = {"LOW":0, "MEDIUM":0, "HIGH":0, "CRITICAL":0}
    for it in issues:
        sev = it.get("severity", "MEDIUM").upper()
        if sev in totals:
            totals[sev] += 1

    summary = {
        "total_issues": len(issues),
        "by_severity": totals,
        "scanned_at": datetime.utcnow().isoformat() + "Z"
    }

    return {"issues": issues, "summary": summary}
