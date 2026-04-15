import boto3


def check_users_without_mfa(**creds):
    iam = boto3.client('iam', **creds)

    users = iam.list_users()['Users']
    users_without_mfa = []

    for user in users:
        mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']

        if len(mfa_devices) == 0:
            users_without_mfa.append(user['UserName'])

    return users_without_mfa


def check_unused_access_keys(**creds):
    iam = boto3.client('iam', **creds)

    unused_keys = []

    users = iam.list_users()['Users']

    for user in users:
        keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']

        for key in keys:
            if key['Status'] == 'Inactive':
                unused_keys.append({
                    "user": user['UserName'],
                    "access_key": key['AccessKeyId']
                })

    return unused_keys