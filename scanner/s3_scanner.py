import boto3


def check_public_buckets(**creds):
    s3 = boto3.client('s3', **creds)

    buckets = s3.list_buckets()['Buckets']

    public_buckets = []

    for bucket in buckets:
        name = bucket['Name']

        try:
            acl = s3.get_bucket_acl(Bucket=name)

            for grant in acl['Grants']:
                if 'AllUsers' in str(grant['Grantee']):
                    public_buckets.append(name)

        except Exception:
            pass

    return public_buckets