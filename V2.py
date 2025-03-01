import json
import boto3
import time
from jinja2 import Template
from datetime import datetime, timezone
import os
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
iam_client = boto3.client('iam')
s3_client = boto3.client('s3')
ec2_client = boto3.client('ec2')
cloudtrail_client = boto3.client('cloudtrail')
rds_client = boto3.client('rds')
kms_client = boto3.client('kms')
efs_client = boto3.client('efs')
config_client = boto3.client('config')

# S3 buckets (set via env vars)
REPORT_BUCKET = os.environ.get('REPORT_BUCKET', 'cis-compliance-reports')
BACKUP_BUCKET = os.environ.get('BACKUP_BUCKET', 'cis-compliance-backups')


# Helper: Generate S3 pre-signed URL
def generate_presigned_url(bucket, key):
    return s3_client.generate_presigned_url('get_object', Params={'Bucket': bucket, 'Key': key}, ExpiresIn=3600)


# Helper functions
def get_trails():
    return cloudtrail_client.describe_trails()['trailimport json
    import boto3
    import time
    from jinja2 import Template
    from datetime import datetime, timezone
    import os
    import logging

    # Configure logging
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # AWS clients - Initialize clients for interacting with various AWS services.
    iam_client = boto3.client('iam')  # Identity and Access Management
    s3_client = boto3.client('s3')  # Simple Storage Service
    ec2_client = boto3.client('ec2')  # Elastic Compute Cloud
    cloudtrail_client = boto3.client('cloudtrail')  # CloudTrail logging
    rds_client = boto3.client('rds')  # Relational Database Service
    kms_client = boto3.client('kms')  # Key Management Service
    efs_client = boto3.client('efs')  # Elastic File System
    config_client = boto3.client('config')  # AWS Config

    # S3 buckets (set via env vars) - Configure the S3 buckets for storing reports and backups.
    REPORT_BUCKET = os.environ.get('REPORT_BUCKET', 'cis-compliance-reports')  # Default: 'cis-compliance-reports'
    BACKUP_BUCKET = os.environ.get('BACKUP_BUCKET', 'cis-compliance-backups')  # Default: 'cis-compliance-backups'

    # Helper: Generate S3 pre-signed URL - Generates a temporary URL for accessing a file in S3.


def generate_presigned_url(bucket, key):
    """
    Generates a pre-signed URL for accessing an object in an S3 bucket.
    Args:
        bucket (str): The name of the S3 bucket.
        key (str): The key (path) of the object in the bucket.
    Returns:
        str: The pre-signed URL.
    """
    return s3_client.generate_presigned_url('get_object', Params={'Bucket': bucket, 'Key': key}, ExpiresIn=3600)


# Helper functions - Utility functions for common tasks.
def get_trails():
    """
    Retrieves a list of CloudTrail trails.
    Returns:
        list: A list of CloudTrail trail dictionaries.
    """
    return cloudtrail_client.describe_trails()['trailList']


def check_resources(get_resources, check_condition, control_id, message_template, remediation_available, remediation):
    """
    Generic function to check a set of AWS resources against a condition.
    Args:
        get_resources (callable): A function that returns a list of resources.
        check_condition (callable): A function that takes a resource and returns True if compliant, False if not.
        control_id (str): The ID of the control being checked.
        message_template (str): A template for the message (e.g., "{}/{} resources compliant").
        remediation_available (bool): Boolean indicating if remediation is possible.
        remediation (str): Message about remediation.
    Returns:
        dict: A dictionary with control status, message, and remediation information.
    """
    try:
        resources = get_resources()  # Get the list of resources
        non_compliant = [r for r in resources if not check_condition(r)]  # Filter out compliant resources
        status = 'PASS' if not non_compliant else 'FAIL'  # Determine overall status
        message = message_template.format(len(non_compliant), len(resources))  # Format message
        return {'control': control_id, 'status': status, 'message': message,
                'remediation_available': remediation_available, 'remediation': remediation}
    except Exception as e:
        return {'control': control_id, 'status': 'ERROR', 'message': f"Failed to check: {str(e)}",
                'remediation_available': False}


# Control Evaluation Functions (All 34 CIS v3.0 Controls) - Functions for evaluating specific security controls.
def check_security_contact():
    """Checks if a security contact (account alias) is set in IAM."""
    try:
        response = iam_client.get_account_alias()
        return {'control': 'Account.1', 'status': 'PASS' if response.get('AccountAliases') else 'FAIL',
                'message': 'Security contact (account alias) set' if response.get(
                    'AccountAliases') else 'No account alias set',
                'remediation_available': False, 'remediation': 'Set account alias via IAM console'}
    except iam_client.exceptions.NoSuchEntityException as e:
        logger.error(f"Error checking security contact: {e}")
        return {'control': 'Account.1', 'status': 'ERROR', 'message': f'Failed to check: {e}',
                'remediation_available': False}
    except Exception as e:
        logger.error(f"Error checking security contact: {e}",
                     exc_info=True)  # add the exc_info to log the whole stack trace.
        return {'control': 'Account.1', 'status': 'ERROR', 'message': 'Failed to check. An unexpected error occurred',
                'remediation_available': False}


def check_cloudtrail_enabled():
    """Checks if CloudTrail is enabled for all regions and records read/write events."""
    trails = get_trails()
    multi_region = any(t.get('IsMultiRegionTrail') for t in trails)
    events = any(
        cloudtrail_client.get_event_selectors(TrailName=t['Name'])['EventSelectors'][0]['ReadWriteType'] in ['All',
                                                                                                             'WriteOnly']
        for t in trails)
    status = 'PASS' if multi_region and events else 'FAIL'
    return {'control': 'CloudTrail.1', 'status': status, 'message': f"Multi-region: {multi_region}, Events: {events}",
            'remediation_available': True, 'remediation': 'Enable multi-region CloudTrail with read/write events'}


def check_cloudtrail_encryption():
    """Checks if CloudTrail trails have KMS encryption enabled."""

    def check(trail):
        return trail.get('KmsKeyId') is not None

    return check_resources(get_trails, check, 'CloudTrail.2', "{}/{} trails lack encryption", True,
                           'Enable KMS encryption on trails')


def check_cloudtrail_validation():
    """Checks if CloudTrail trails have log file validation enabled."""

    def check(trail):
        return trail.get('LogFileValidationEnabled', False)

    return check_resources(get_trails, check, 'CloudTrail.4', '{}/{} trails lack log validation', True,
                           'Enable log file validation on trails')


def check_cloudtrail_s3_logging():
    """Checks if CloudTrail trail buckets have S3 access logging enabled."""

    def check(trail):
        return s3_client.get_bucket_logging(Bucket=trail['S3BucketName']).get('LoggingEnabled') is not None

    return check_resources(get_trails, check, 'CloudTrail.7', '{}/{} trail buckets lack logging', True,
                           'Enable S3 access logging on trail buckets')


def check_config_enabled():
    """Checks if AWS Config is enabled."""
    status = config_client.describe_configuration_recorders()['ConfigurationRecorders']
    return {'control': 'Config.1', 'status': 'PASS' if status else 'FAIL',
            'message': 'Config enabled' if status else 'Config not enabled',
            'remediation_available': True, 'remediation': 'Enable AWS Config'}


def check_vpc_default_sg():
    """Checks if default VPC security groups have any ingress or egress rules."""
    sgs = ec2_client.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': ['default']}])['SecurityGroups']
    non_compliant = [sg['GroupId'] for sg in sgs if sg['IpPermissions'] or sg['IpPermissionsEgress']]
    return {'control': 'EC2.2', 'status': 'PASS' if not non_compliant else 'FAIL',
            'message': f"{len(non_compliant)}/{len(sgs)} default SGs have rules",
            'remediation_available': True, 'remediation': 'Remove rules from default SGs'}


def check_vpc_flow_logs():
    """Checks if VPC flow logs are enabled."""
    logs = ec2_client.describe_flow_logs()['FlowLogs']
    return {'control': 'EC2.6', 'status': 'PASS' if logs else 'FAIL',
            'message': 'Flow logs enabled' if logs else 'No flow logs found',
            'remediation_available': True, 'remediation': 'Enable VPC flow logs'}


def check_ebs_encryption():
    """Checks if EBS default encryption is enabled."""
    status = ec2_client.get_ebs_encryption_by_default()['EbsEncryptionByDefault']
    return {'control': 'EC2.7', 'status': 'PASS' if status else 'FAIL',
            'message': 'EBS default encryption enabled' if status else 'EBS encryption not default',
            'remediation_available': True, 'remediation': 'Enable EBS default encryption'}


def check_imdsv2():
    """Checks if EC2 instances have IMDSv2 enabled."""
    instances = ec2_client.describe_instances()['Reservations']
    non_compliant = [i['Instances'][0]['InstanceId'] for i in instances if
                     i['Instances'][0]['MetadataOptions']['HttpTokens'] != 'required']
    return {'control': 'EC2.8', 'status': 'PASS' if not non_compliant else 'FAIL',
            'message': f"{len(non_compliant)} instances lack IMDSv2",
            'remediation_available': True, 'remediation': 'Enforce IMDSv2 on instances'}


def check_nacl_open_ports():
    """Checks if Network ACLs allow open ports 22 or 3389 from 0.0.0.0/0."""
    nacls = ec2_client.describe_network_acls()['NetworkAcls']
    open = [n['NetworkAclId'] for n in nacls for e in n['Entries'] if
            e['CidrBlock'] == '0.0.0.0/0' and e['RuleAction'] == 'allow' and (
                    e['PortRange']['From'] in [22, 3389] or e['PortRange']['To'] in [22, 3389])]
    return {'control': 'EC2.21', 'status': 'PASS' if not open else 'FAIL',
            'message': f"{len(open)} NACLs allow 22/3389 from 0.0.0.0/0",
            'remediation_available': True, 'remediation': 'Restrict NACL ingress'}


def check_sg_open_ipv4():
    """Checks if Security Groups allow open ports 22 or 3389 from 0.0.0.0/0 (IPv4)."""

    def check(sg):
        return all('0.0.0.0/0' not in [r['CidrIp'] for r in p['IpRanges']] or not (
                p['FromPort'] in [22, 3389] or p['ToPort'] in [22, 3389]) for p in sg['IpPermissions'])

    return check_resources(lambda: ec2_client.describe_security_groups()['SecurityGroups'], check, 'EC2.53',
                           '{}/{} SGs allow 22/3389 from 0.0.0.0/0', True, 'Restrict SG ingress from IPv4')


def check_sg_open_ipv6():
    """Checks if Security Groups allow open ports 22 or 3389 from ::/0 (IPv6)."""
    sgs = ec2_client.describe_security_groups()['SecurityGroups']
    open = [sg['GroupId'] for sg in sgs for p in sg['IpPermissions'] if
            '::/0' in [r['CidrIpv6'] for r in p.get('Ipv6Ranges', [])] and (
                    p['FromPort'] in [22, 3389] or p['ToPort'] in [22, 3389])]
    return {'control': 'EC2.54', 'status': 'PASS' if not open else 'FAIL',
            'message': f"{len(open)} SGs allow 22/3389 from ::/0",
            'remediation_available': True, 'remediation': 'Restrict SG ingress from IPv6'}List']


def check_resources(get_resources, check_condition, control_id, message_template, remediation_available, remediation):
    """
    Generic function to check a set of AWS resources against a condition.
    Args:
        get_resources: A function that returns a list of resources.
        check_condition: A function that takes a resource and returns True if compliant, False if not.
        control_id: The ID of the control being checked.
        message_template: A template for the message (e.g., "{}/{} resources compliant").
        remediation_available: Boolean indicating if remediation is possible.
        remediation: Message about remediation.
    Returns:
        A dictionary with control status.
    """
    try:
        resources = get_resources()
        non_compliant = [r for r in resources if not check_condition(r)]
        status = 'PASS' if not non_compliant else 'FAIL'
        message = message_template.format(len(non_compliant), len(resources))
        return {'control': control_id, 'status': status, 'message': message,
                'remediation_available': remediation_available, 'remediation': remediation}
    except Exception as e:
        return {'control': control_id, 'status': 'ERROR', 'message': f"Failed to check: {str(e)}",
                'remediation_available': False}


# Control Evaluation Functions (All 34 CIS v3.0 Controls)
def check_security_contact():
    try:
        response = iam_client.get_account_alias()
        return {'control': 'Account.1', 'status': 'PASS' if response.get('AccountAliases') else 'FAIL',
                'message': 'Security contact (account alias) set' if response.get(
                    'AccountAliases') else 'No account alias set',
                'remediation_available': False, 'remediation': 'Set account alias via IAM console'}
    except iam_client.exceptions.NoSuchEntityException as e:
        logger.error(f"Error checking security contact: {e}")
        return {'control': 'Account.1', 'status': 'ERROR', 'message': f'Failed to check: {e}',
                'remediation_available': False}
    except Exception as e:
        logger.error(f"Error checking security contact: {e}",
                     exc_info=True)  # add the exc_info to log the whole stack trace.
        return {'control': 'Account.1', 'status': 'ERROR', 'message': 'Failed to check. An unexpected error occurred',
                'remediation_available': False}


def check_cloudtrail_enabled():
    trails = get_trails()
    multi_region = any(t.get('IsMultiRegionTrail') for t in trails)
    events = any(
        cloudtrail_client.get_event_selectors(TrailName=t['Name'])['EventSelectors'][0]['ReadWriteType'] in ['All',
                                                                                                             'WriteOnly']
        for t in trails)
    status = 'PASS' if multi_region and events else 'FAIL'
    return {'control': 'CloudTrail.1', 'status': status, 'message': f"Multi-region: {multi_region}, Events: {events}",
            'remediation_available': True, 'remediation': 'Enable multi-region CloudTrail with read/write events'}


def check_cloudtrail_encryption():
    def check(trail):
        return trail.get('KmsKeyId') is not None

    return check_resources(get_trails, check, 'CloudTrail.2', "{}/{} trails lack encryption", True,
                           'Enable KMS encryption on trails')


def check_cloudtrail_validation():
    def check(trail):
        return trail.get('LogFileValidationEnabled', False)

    return check_resources(get_trails, check, 'CloudTrail.4', '{}/{} trails lack log validation', True,
                           'Enable log file validation on trails')


def check_cloudtrail_s3_logging():
    def check(trail):
        return s3_client.get_bucket_logging(Bucket=trail['S3BucketName']).get('LoggingEnabled') is not None

    return check_resources(get_trails, check, 'CloudTrail.7', '{}/{} trail buckets lack logging', True,
                           'Enable S3 access logging on trail buckets')


def check_config_enabled():
    status = config_client.describe_configuration_recorders()['ConfigurationRecorders']
    return {'control': 'Config.1', 'status': 'PASS' if status else 'FAIL',
            'message': 'Config enabled' if status else 'Config not enabled',
            'remediation_available': True, 'remediation': 'Enable AWS Config'}


def check_vpc_default_sg():
    sgs = ec2_client.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': ['default']}])['SecurityGroups']
    non_compliant = [sg['GroupId'] for sg in sgs if sg['IpPermissions'] or sg['IpPermissionsEgress']]
    return {'control': 'EC2.2', 'status': 'PASS' if not non_compliant else 'FAIL',
            'message': f"{len(non_compliant)}/{len(sgs)} default SGs have rules",
            'remediation_available': True, 'remediation': 'Remove rules from default SGs'}


def check_vpc_flow_logs():
    logs = ec2_client.describe_flow_logs()['FlowLogs']
    return {'control': 'EC2.6', 'status': 'PASS' if logs else 'FAIL',
            'message': 'Flow logs enabled' if logs else 'No flow logs found',
            'remediation_available': True, 'remediation': 'Enable VPC flow logs'}


def check_ebs_encryption():
    status = ec2_client.get_ebs_encryption_by_default()['EbsEncryptionByDefault']
    return {'control': 'EC2.7', 'status': 'PASS' if status else 'FAIL',
            'message': 'EBS default encryption enabled' if status else 'EBS encryption not default',
            'remediation_available': True, 'remediation': 'Enable EBS default encryption'}


def check_imdsv2():
    instances = ec2_client.describe_instances()['Reservations']
    non_compliant = [i['Instances'][0]['InstanceId'] for i in instances if
                     i['Instances'][0]['MetadataOptions']['HttpTokens'] != 'required']
    return {'control': 'EC2.8', 'status': 'PASS' if not non_compliant else 'FAIL',
            'message': f"{len(non_compliant)} instances lack IMDSv2",
            'remediation_available': True, 'remediation': 'Enforce IMDSv2 on instances'}


def check_nacl_open_ports():
    nacls = ec2_client.describe_network_acls()['NetworkAcls']
    open = [n['NetworkAclId'] for n in nacls for e in n['Entries'] if
            e['CidrBlock'] == '0.0.0.0/0' and e['RuleAction'] == 'allow' and (
                        e['PortRange']['From'] in [22, 3389] or e['PortRange']['To'] in [22, 3389])]
    return {'control': 'EC2.21', 'status': 'PASS' if not open else 'FAIL',
            'message': f"{len(open)} NACLs allow 22/3389 from 0.0.0.0/0",
            'remediation_available': True, 'remediation': 'Restrict NACL ingress'}


def check_sg_open_ipv4():
    def check(sg):
        return all('0.0.0.0/0' not in [r['CidrIp'] for r in p['IpRanges']] or not (
                    p['FromPort'] in [22, 3389] or p['ToPort'] in [22, 3389]) for p in sg['IpPermissions'])

    return check_resources(lambda: ec2_client.describe_security_groups()['SecurityGroups'], check, 'EC2.53',
                           '{}/{} SGs allow 22/3389 from 0.0.0.0/0', True, 'Restrict SG ingress from IPv4')


def check_sg_open_ipv6():
    sgs = ec2_client.describe_security_groups()['SecurityGroups']
    open = [sg['GroupId'] for sg in sgs for p in sg['IpPermissions'] if
            '::/0' in [r['CidrIpv6'] for r in p.get('Ipv6Ranges', [])] and (
                        p['FromPort'] in [22, 3389] or p['ToPort'] in [22, 3389])]
    return {'control': 'EC2.54', 'status': 'PASS' if not open else 'FAIL',
            'message': f"{len(open)} S
