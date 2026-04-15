import boto3


def check_cloudtrail_status(**creds):
    client = boto3.client('cloudtrail', **creds)

    trails = client.describe_trails()['trailList']

    if len(trails) == 0:
        return "CloudTrail Disabled"

    return "CloudTrail Enabled"