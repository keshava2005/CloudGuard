import boto3


def check_open_security_groups(**creds):
    ec2 = boto3.client('ec2', **creds)

    response = ec2.describe_security_groups()

    open_groups = []

    for sg in response['SecurityGroups']:

        for permission in sg['IpPermissions']:

            for ip_range in permission.get('IpRanges', []):
                if ip_range['CidrIp'] == '0.0.0.0/0':

                    open_groups.append({
                        "GroupName": sg['GroupName'],
                        "Port": permission.get('FromPort', 'All')
                    })

    return open_groups