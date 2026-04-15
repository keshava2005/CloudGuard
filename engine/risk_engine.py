def calculate_risk(mfa_users, public_buckets, open_security_groups, cloudtrail_status):

    score = 100

    score -= len(mfa_users) * 10
    score -= len(public_buckets) * 20
    score -= len(open_security_groups) * 25

    if cloudtrail_status == "CloudTrail Disabled":
        score -= 30

    if score >= 80:
        risk = "LOW"
    elif score >= 50:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    return score, risk