def calculate_risk(mfa_users, public_buckets, open_security_groups, cloudtrail_status):
    """
    Scoring breakdown (starts at 100):

    IAM — Users without MFA      : -10 per user,  capped at -30
    S3  — Public buckets          : -15 per bucket, capped at -30
    EC2 — Open security groups    : -10 per group,  capped at -25
    CloudTrail — Disabled         : -15 flat penalty

    Score is clamped between 0 and 100.
    Risk levels:
        LOW    : 75 – 100   (good security posture)
        MEDIUM : 40 – 74    (some risks present)
        HIGH   : 0  – 39    (critical issues found)
    """

    score = 100

    # IAM deduction — max 30 points lost
    iam_penalty = min(len(mfa_users) * 10, 30)
    score -= iam_penalty

    # S3 deduction — max 30 points lost
    s3_penalty = min(len(public_buckets) * 15, 30)
    score -= s3_penalty

    # EC2 deduction — max 25 points lost
    ec2_penalty = min(len(open_security_groups) * 10, 25)
    score -= ec2_penalty

    # CloudTrail deduction — flat 15 points
    ct = str(cloudtrail_status).strip().lower()
    if ct in ("disabled", "cloudtrail disabled", "false", "none", "unknown"):
        score -= 15

    # Clamp score between 0 and 100
    score = max(0, min(100, score))

    if score >= 75:
        risk = "LOW"
    elif score >= 40:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    return score, risk