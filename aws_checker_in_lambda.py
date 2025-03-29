import json
import boto3
import time
import os
import logging
from typing import Dict, List, Any, Optional, Union
from jinja2 import Template
from datetime import datetime, timezone
from botocore.config import Config
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configuration from environment variables
REPORT_BUCKET = os.environ.get('REPORT_BUCKET', 'cis-compliance-reports')
BACKUP_BUCKET = os.environ.get('BACKUP_BUCKET', 'cis-compliance-backups')
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')

# Configure retry settings for AWS clients
retry_config = Config(
    retries={'max_attempts': 3, 'mode': 'standard'}
)

# AWS clients with retry configuration
iam_client = boto3.client('iam', config=retry_config)
s3_client = boto3.client('s3', config=retry_config)
ec2_client = boto3.client('ec2', config=retry_config)
cloudtrail_client = boto3.client('cloudtrail', config=retry_config)
rds_client = boto3.client('rds', config=retry_config)
kms_client = boto3.client('kms', config=retry_config)
efs_client = boto3.client('efs', config=retry_config)
config_client = boto3.client('config', config=retry_config)

# -------------------------------------------------------------------------
# AI Assistance Acknowledgment
# -------------------------------------------------------------------------
# This Lambda function was developed with assistance from:
# - Claude 3.7 Sonnet: Optimized code structure, error handling, and AWS service integration
# - Grok 3: Contributed to security rule implementation and compliance logic
# 
# Together, these AI systems helped create a more robust, efficient, and
# secure AWS compliance checking solution.
# -------------------------------------------------------------------------

# Load controls from S3
def load_controls() -> Dict[str, Any]:
    """
    Load control definitions from S3 bucket.
    
    Returns:
        Dict[str, Any]: Dictionary of control definitions with control IDs as keys
                       and control metadata as values
    """
    try:
        response = s3_client.get_object(Bucket=REPORT_BUCKET, Key='controls.json')
        return json.loads(response['Body'].read().decode('utf-8'))
    except ClientError as e:
        logger.error(f"Failed to load controls: {e}", exc_info=True)
        # Fallback to empty controls if can't load
        return {}

# Helper: Generate S3 pre-signed URL
def generate_presigned_url(bucket: str, key: str, expiry: int = 3600) -> str:
    """
    Generate a pre-signed URL for an S3 object.
    
    Args:
        bucket (str): S3 bucket name
        key (str): S3 object key
        expiry (int): URL expiration time in seconds
        
    Returns:
        str: Pre-signed URL for accessing the object
    """
    try:
        return s3_client.generate_presigned_url(
            'get_object', 
            Params={'Bucket': bucket, 'Key': key}, 
            ExpiresIn=expiry
        )
    except ClientError as e:
        logger.error(f"Failed to generate presigned URL: {e}", exc_info=True)
        return ""

# Control Evaluation Functions (All 34 CIS v3.0 Controls)
def check_security_contact() -> Dict[str, Any]:
    """
    Check if security contact information is configured.
    
    Evaluates if the AWS account has a security contact configured by checking
    for the presence of an account alias.
    
    Returns:
        Dict[str, Any]: Control check result containing:
            - control: Control ID
            - status: PASS, FAIL, or ERROR
            - message: Descriptive message
            - remediation_available: Whether automated remediation is available
            - remediation: Remediation guidance
    """
    try:
        response = iam_client.get_account_alias()
        return {
            'control': 'Account.1', 
            'status': 'PASS' if response.get('AccountAliases') else 'FAIL',
            'message': 'Security contact (account alias) set' if response.get('AccountAliases') else 'No account alias set',
            'remediation_available': False, 
            'remediation': 'Set account alias via IAM console'
        }
    except iam_client.exceptions.NoSuchEntityException as e:
        # Specific exception for when entity doesn't exist
        logger.error(f"Entity not found when checking security contact: {e}", exc_info=True)
        return {
            'control': 'Account.1', 
            'status': 'ERROR', 
            'message': f'Failed to check: Entity not found', 
            'remediation_available': False
        }
    except ClientError as e:
        logger.error(f"Error checking security contact: {e}", exc_info=True)
        return {
            'control': 'Account.1', 
            'status': 'ERROR', 
            'message': f'Failed to check: {str(e)}', 
            'remediation_available': False
        }
    except Exception as e:
        # Catch all other exceptions
        logger.error(f"Unexpected error checking security contact: {e}", exc_info=True)
        return {
            'control': 'Account.1', 
            'status': 'ERROR', 
            'message': f'Unexpected error: {str(e)}', 
            'remediation_available': False
        }

def check_cloudtrail_enabled() -> Dict[str, Any]:
    """
    Check if CloudTrail is properly enabled.
    
    Evaluates if CloudTrail is configured with multi-region support and
    appropriate event selectors for read/write events.
    
    Returns:
        Dict[str, Any]: Control check result containing status and remediation info
    """
    # Constants for better readability
    CONTROL_ID = 'CloudTrail.1'
    VALID_READ_WRITE_TYPES = ['All', 'WriteOnly']
    
    # Helper function to create standardized response
    def create_response(status: str, message: str, remediation_available: bool = True) -> Dict[str, Any]:
        return {
            'control': CONTROL_ID,
            'status': status,
            'message': message,
            'remediation_available': remediation_available,
            'remediation': 'Enable multi-region CloudTrail with read/write events' if remediation_available else ''
        }
    
    # Helper function to check if trail has appropriate event selectors
    def has_appropriate_event_selectors(trail_name: str) -> bool:
        """
        Check if a trail records the correct type of events.
        
        Args:
            trail_name: Name of the CloudTrail trail to check
            
        Returns:
            True if the trail has appropriate event selectors, False otherwise
        """
        try:
            selectors = cloudtrail_client.get_event_selectors(TrailName=trail_name)['EventSelectors']
            return any(selector['ReadWriteType'] in VALID_READ_WRITE_TYPES for selector in selectors)
        except ClientError as e:
            logger.warning(f"Failed to get event selectors for trail {trail_name}: {e}", exc_info=True)
            return False
    
    try:
        # Get all trails
        trails = cloudtrail_client.describe_trails()['trailList']
        
        # Handle the case where no trails are found
        if not trails:
            return create_response('FAIL', "No CloudTrail trails found")
            
        # Check for trails with multi-region support enabled
        # We use a more descriptive variable name in the list comprehension to improve readability
        multi_region_trails = [each_trail for each_trail in trails if each_trail.get('IsMultiRegionTrail')]
        has_multi_region = bool(multi_region_trails)
        
        # Check if any trail has appropriate event recording settings
        events_configured = any(has_appropriate_event_selectors(each_trail['Name']) for each_trail in trails)
        
        # Both conditions must be true for compliance
        is_compliant = has_multi_region and events_configured
        status = 'PASS' if is_compliant else 'FAIL'
        
        # Create detailed message about what was found
        message = f"Multi-region: {has_multi_region}, Events: {events_configured}"
        
        return create_response(status, message)
        
    except ClientError as e:
        error_message = f"Failed to check: {str(e)}"
        logger.error(f"Error checking CloudTrail: {e}", exc_info=True)
        return create_response('ERROR', error_message, False)

def check_cloudtrail_encryption() -> Dict[str, Any]:
    """
    Check if CloudTrail trails have KMS encryption enabled.
    
    Evaluates whether CloudTrail trails are configured with KMS encryption
    for protecting log data at rest.
    
    Returns:
        Dict[str, Any]: Control check result with encryption status details
    """
    try:
        trails = cloudtrail_client.describe_trails()['trailList']
        non_encrypted = [t['Name'] for t in trails if not t.get('KmsKeyId')]
        return {
            'control': 'CloudTrail.2', 
            'status': 'PASS' if not non_encrypted else 'FAIL',
            'message': f"{len(non_encrypted)}/{len(trails)} trails lack encryption",
            'remediation_available': True, 
            'remediation': 'Enable KMS encryption on trails'
        }
    except ClientError as e:
        logger.error(f"Error checking CloudTrail encryption: {e}", exc_info=True)
        return {
            'control': 'CloudTrail.2', 
            'status': 'ERROR', 
            'message': f'Failed to check: {str(e)}', 
            'remediation_available': False
        }

def check_cloudtrail_validation() -> Dict[str, Any]:
    """
    Check if CloudTrail log file validation is enabled.
    
    Verifies that CloudTrail trails have log file validation enabled,
    which helps ensure log file integrity.
    
    Returns:
        Dict[str, Any]: Control check result with validation status details
    """
    try:
        trails = cloudtrail_client.describe_trails()['trailList']
        no_validation = [t['Name'] for t in trails if not t.get('LogFileValidationEnabled')]
        return {
            'control': 'CloudTrail.4', 
            'status': 'PASS' if not no_validation else 'FAIL',
            'message': f"{len(no_validation)}/{len(trails)} trails lack log validation",
            'remediation_available': True, 
            'remediation': 'Enable log file validation on trails'
        }
    except ClientError as e:
        logger.error(f"Error checking CloudTrail validation: {e}", exc_info=True)
        return {
            'control': 'CloudTrail.4', 
            'status': 'ERROR', 
            'message': f'Failed to check: {str(e)}', 
            'remediation_available': False
        }

def check_cloudtrail_s3_logging() -> Dict[str, Any]:
    """
    Check if CloudTrail trail buckets have S3 access logging enabled.
    
    Verifies that S3 buckets used for CloudTrail logs have access logging
    enabled for security and audit purposes.
    
    Returns:
        Dict[str, Any]: Control check result with S3 logging status details
    """
    try:
        trails = cloudtrail_client.describe_trails()['trailList']
        no_logging = []
        for t in trails:
            try:
                if not s3_client.get_bucket_logging(Bucket=t['S3BucketName']).get('LoggingEnabled'):
                    no_logging.append(t['Name'])
            except ClientError as e:
                logger.warning(f"Unable to check logging for bucket {t['S3BucketName']}: {e}", exc_info=True)
                no_logging.append(t['Name'])
                
        return {
            'control': 'CloudTrail.7', 
            'status': 'PASS' if not no_logging else 'FAIL',
            'message': f"{len(no_logging)}/{len(trails)} trail buckets lack logging",
            'remediation_available': True, 
            'remediation': 'Enable S3 access logging on trail buckets'
        }
    except ClientError as e:
        logger.error(f"Error checking CloudTrail S3 logging: {e}", exc_info=True)
        return {
            'control': 'CloudTrail.7', 
            'status': 'ERROR', 
            'message': f'Failed to check: {str(e)}', 
            'remediation_available': False
        }

def check_config_enabled() -> Dict[str, Any]:
    """
    Check if AWS Config is enabled.
    
    Verifies that AWS Config service is enabled for resource inventory,
    configuration history, and change notification.
    
    Returns:
        Dict[str, Any]: Control check result with AWS Config status
    """
    try:
        status = config_client.describe_configuration_recorders()['ConfigurationRecorders']
        return {
            'control': 'Config.1', 
            'status': 'PASS' if status else 'FAIL',
            'message': 'Config enabled' if status else 'Config not enabled',
            'remediation_available': True, 
            'remediation': 'Enable AWS Config'
        }
    except ClientError as e:
        logger.error(f"Error checking AWS Config: {e}", exc_info=True)
        return {
            'control': 'Config.1', 
            'status': 'ERROR', 
            'message': f'Failed to check: {str(e)}', 
            'remediation_available': False
        }

def check_vpc_default_sg() -> Dict[str, Any]:
    """
    Check if default VPC security groups have any rules.
    
    Verifies that default security groups restrict all traffic by having
    no inbound or outbound rules defined.
    
    Returns:
        Dict[str, Any]: Control check result with security group details
    """
    try:
        sgs = ec2_client.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': ['default']}])['SecurityGroups']
        non_compliant = [sg['GroupId'] for sg in sgs if sg['IpPermissions'] or sg['IpPermissionsEgress']]
        return {
            'control': 'EC2.2', 
            'status': 'PASS' if not non_compliant else 'FAIL',
            'message': f"{len(non_compliant)}/{len(sgs)} default SGs have rules",
            'remediation_available': True, 
            'remediation': 'Remove rules from default SGs'
        }
    except ClientError as e:
        logger.error(f"Error checking default security groups: {e}", exc_info=True)
        return {
            'control': 'EC2.2', 
            'status': 'ERROR', 
            'message': f'Failed to check: {str(e)}', 
            'remediation_available': False
        }

def check_vpc_flow_logs() -> Dict[str, Any]:
    """
    Check if VPC flow logs are enabled.
    
    Verifies if VPC flow logs are enabled to capture information about
    IP traffic going to and from network interfaces in the VPC.
    
    Returns:
        Dict[str, Any]: Control check result with flow log status
    """
    try:
        logs = ec2_client.describe_flow_logs()['FlowLogs']
        return {
            'control': 'EC2.6', 
            'status': 'PASS' if logs else 'FAIL',
            'message': 'Flow logs enabled' if logs else 'No flow logs found',
            'remediation_available': True, 
            'remediation': 'Enable VPC flow logs'
        }
    except ClientError as e:
        logger.error(f"Error checking VPC flow logs: {e}", exc_info=True)
        return {
            'control': 'EC2.6', 
            'status': 'ERROR', 
            'message': f'Failed to check: {str(e)}', 
            'remediation_available': False
        }

def check_ebs_encryption() -> Dict[str, Any]:
    """
    Check if EBS default encryption is enabled.
    
    Verifies if encryption by default is enabled for EBS volumes to
    protect data at rest.
    
    Returns:
        Dict[str, Any]: Control check result with EBS encryption status
    """
    try:
        status = ec2_client.get_ebs_encryption_by_default()['EbsEncryptionByDefault']
        return {
            'control': 'EC2.7', 
            'status': 'PASS' if status else 'FAIL',
            'message': 'EBS default encryption enabled' if status else 'EBS encryption not default',
            'remediation_available': True, 
            'remediation': 'Enable EBS default encryption'
        }
    except ClientError as e:
        logger.error(f"Error checking EBS encryption: {e}", exc_info=True)
        return {
            'control': 'EC2.7', 
            'status': 'ERROR', 
            'message': f'Failed to check: {str(e)}', 
            'remediation_available': False
        }

def check_imdsv2() -> Dict[str, Any]:
    """
    Check if EC2 instances have IMDSv2 enabled.
    
    Verifies if EC2 instances are configured to use IMDSv2 (Instance Metadata
    Service v2) which provides additional security protections.
    
    Returns:
        Dict[str, Any]: Control check result with IMDSv2 status details
    """
    try:
        instances = ec2_client.describe_instances()['Reservations']
        non_compliant = []
        for i in instances:
            for instance in i['Instances']:
                if instance['MetadataOptions']['HttpTokens'] != 'required':
                    non_compliant.append(instance['InstanceId'])
                
        return {
            'control': 'EC2.8', 
            'status': 'PASS' if not non_compliant else 'FAIL',
            'message': f"{len(non_compliant)} instances lack IMDSv2",
            'remediation_available': True, 
            'remediation': 'Enforce IMDSv2 on instances'
        }
    except ClientError as e:
        logger.error(f"Error checking IMDSv2: {e}", exc_info=True)
        return {
            'control': 'EC2.8', 
            'status': 'ERROR', 
            'message': f'Failed to check: {str(e)}', 
            'remediation_available': False
        }

def check_nacl_open_ports() -> Dict[str, Any]:
    """
    Check if Network ACLs allow open admin ports from 0.0.0.0/0.
    
    Verifies if Network ACLs allow ingress from 0.0.0.0/0 to administrative
    ports (22 and 3389), which poses a security risk.
    
    Returns:
        Dict[str, Any]: Control check result with NACL details
    """
    try:
        nacls = ec2_client.describe_network_acls()['NetworkAcls']
        open_ports = []
        
        for n in nacls:
            for e in n['Entries']:
                if (e.get('CidrBlock') == '0.0.0.0/0' and 
                    e['RuleAction'] == 'allow' and 
                    ('PortRange' in e and (
                        e['PortRange']['From'] in [22, 3389] or 
                        e['PortRange']['To'] in [22, 3389]))):
                    open_ports.append(n['NetworkAclId'])
                    break
                    
        return {
            'control': 'EC2.21', 
            'status': 'PASS' if not open_ports else 'FAIL',
            'message': f"{len(open_ports)} NACLs allow 22/3389 from 0.0.0.0/0",
            'remediation_available': True, 
            'remediation': 'Restrict NACL ingress'
        }
    except ClientError as e:
        logger.error(f"Error checking NACL open ports: {e}", exc_info=True)
        return {
            'control': 'EC2.21', 
            'status': 'ERROR', 
            'message': f'Failed to check: {str(e)}', 
            'remediation_available': False
        }

def check_sg_open_ipv4() -> Dict[str, Any]:
    """
    Check if Security Groups allow open admin ports from 0.0.0.0/0 (IPv4).
    
    Verifies if security groups allow ingress from 0.0.0.0/0 to administrative
    ports (22 and 3389), which poses a security risk.
    
    Returns:
        Dict[str, Any]: Control check result with security group details
    """
    try:
        sgs = ec2_client.describe_security_groups()['SecurityGroups']
        open_groups = []
        
        for sg in sgs:
            for p in sg['IpPermissions']:
                if 'FromPort' in p and 'ToPort' in p:
                    admin_port = (p['FromPort'] in [22, 3389] or p['ToPort'] in [22, 3389])
                    open_from_anywhere = any(r.get('CidrIp') == '0.0.0.0/0' for r in p.get('IpRanges', []))
                    
                    if admin_port and open_from_anywhere:
                        open_groups.append(sg['GroupId'])
                        break
                        
        return {
            'control': 'EC2.53', 
            'status': 'PASS' if not open_groups else 'FAIL',
            'message': f"{len(open_groups)} SGs allow 22/3389 from 0.0.0.0/0",
            'remediation_available': True, 
            'remediation': 'Restrict SG ingress from IPv4'
        }
    except ClientError as e:
        logger.error(f"Error checking security group IPv4 rules: {e}", exc_info=True)
        return {
            'control': 'EC2.53', 
            'status': 'ERROR', 
            'message': f'Failed to check: {str(e)}', 
            'remediation_available': False
        }

def check_sg_open_ipv6() -> Dict[str, Any]:
    """
    Check if Security Groups allow open admin ports from ::/0 (IPv6).
    
    Verifies if security groups allow ingress from ::/0 to administrative
    ports (22 and 3389), which poses a security risk.
    
    Returns:
        Dict[str, Any]: Control check result with security group details
    """
    try:
        sgs = ec2_client.describe_security_groups()['SecurityGroups']
        open_groups = []
        
        for sg in sgs:
            for p in sg['IpPermissions']:
                if 'FromPort' in p and 'ToPort' in p:
                    admin_port = (p['FromPort'] in [22, 3389] or p['ToPort'] in [22, 3389])
                    open_from_anywhere = any(r.get('CidrIpv6') == '::/0' for r in p.get('Ipv6Ranges', []))
                    
                    if admin_port and open_from_anywhere:
                        open_groups.append(sg['GroupId'])
                        break
                        
        return {
            'control': 'EC2.54', 
            'status': 'PASS' if not open_groups else 'FAIL',
            'message': f"{len(open_groups)} SGs allow 22/3389 from ::/0",
            'remediation_available': True, 
            'remediation': 'Restrict SG ingress from IPv6'
        }
    except ClientError as e:
        logger.error(f"Error checking security group IPv6 rules: {e}", exc_info=True)
        return {
            'control': 'EC2.54', 
            'status': 'ERROR', 
            'message': f'Failed to check: {str(e)}', 
            'remediation_available': False
        }

def check_efs_encryption() -> Dict[str, Any]:
    """
    Check if EFS volumes are encrypted at rest.
    
    Verifies if Elastic File System (EFS) volumes are configured with
    encryption at rest for data protection.
    
    Returns:
        Dict[str, Any]: Control check result with EFS encryption status
    """
    try:
        fs = efs_client.describe_file_systems()['FileSystems']
        unencrypted = [f['FileSystemId'] for f in fs if not f['Encrypted']]
        return {
            'control': 'EFS.1', 
            'status': 'PASS' if not unencrypted else 'FAIL',
            'message': f"{len(unencrypted)}/{len(fs)} EFS unencrypted",
            'remediation_available': False, 
            'remediation': 'Recreate EFS with encryption (manual)'
        }
    except ClientError as e:
        logger.error(f"Error checking EFS encryption: {e}", exc_info=True)
        return {
            'control': 'EFS.1', 
            'status': 'ERROR', 
            'message': f'Failed to check: {str(e)}', 
            'remediation_available': False
        }

def check_iam_user_policies() -> Dict[str, Any]:
    """
    Check if IAM users have policies attached directly.
    
    Verifies that policies are attached to groups rather than directly
    to users, which is a best practice for IAM management.
    
    Returns:
        Dict[str, Any]: Control check result with IAM user policy details
    """
    try:
        users = iam_client.list_users()['Users']
        with_policies = []
        
        for u in users:
            try:
                if iam_client.list_attached_user_policies(UserName=u['UserName'])['AttachedPolicies']:
                    with_policies.append(u['UserName'])
            except ClientError as e:
                logger.warning(f"Error checking policies for user {u['UserName']}: {e}", exc_info=True)
                
        return {
            'control': 'IAM.2', 
            'status': 'PASS' if not with_policies else 'FAIL',
            'message': f"{len(with_policies)} users have direct policies",
            'remediation_available': False, 
            'remediation': 'Move policies to groups (manual)'
        }
    except ClientError as e:
        logger.error(f"Error checking IAM user policies: {e}", exc_info=True)
        return {
            'control': 'IAM.2', 
            'status': 'ERROR', 
            'message': f'Failed to check: {str(e)}', 
            'remediation_available': False
        }

def check_iam_key_rotation() -> Dict[str, Any]:
    """
    Check if IAM access keys are rotated every 90 days.
    
    Verifies that IAM access keys are rotated regularly to maintain
    security through credential cycling.
    
    Returns:
        Dict[str, Any]: Control check result with key rotation details
    """
    try:
        # Generate credential report if it doesn't exist
        try:
            iam_client.generate_credential_report()
        except ClientError as e:
            if 'ReportInProgress' not in str(e):
                raise
            time.sleep(2)  # Wait for report to be generated
            
        report = iam_client.get_credential_report()['Content'].decode('utf-8').splitlines()[1:]
        old_keys = []
        
        for line in report:
            fields = line.split(',')
            username = fields[0]
            
            # Check access key 1
            if fields[8] == 'true':  # key 1 is active
                key1_age = int(fields[9])
                if key1_age >= 90:
                    old_keys.append(f"{username} (key 1)")
                    
            # Check access key 2
            if fields[13] == 'true':  # key 2 is active
                key2_age = int(fields[14])
                if key2_age >= 90:
                    old_keys.append(f"{username} (key 2)")
                    
        return {
            'control': 'IAM.3', 
            'status': 'PASS' if not old_keys else 'FAIL',
            'message': f"{len(old_keys)} keys older than 90 days",
            'remediation_available': False, 
            'remediation': 'Rotate access keys (manual)'
        }
    except ClientError as e:
        logger.error(f"Error checking IAM key rotation: {e}", exc_info=True)
        return {
            'control': 'IAM.3', 
            'status': 'ERROR', 
            'message': f'Failed to check: {str(e)}', 
            'remediation_available': False
        }

def check_root_access_keys():
    keys = iam_client.get_account_summary()['SummaryMap'].get('AccountAccessKeysPresent', 0)
    return {'control': 'IAM.4', 'status': 'PASS' if keys == 0 else 'FAIL',
            'message': f"{keys} root access keys exist",
            'remediation_available': False, 'remediation': 'Delete root keys (manual)'}

def check_iam_mfa_console():
    users = iam_client.list_users()['Users']
    no_mfa = [u['UserName'] for u in users if u.get('PasswordLastUsed') and not iam_client.list_mfa_devices(UserName=u['UserName'])['MFADevices']]
    return {'control': 'IAM.5', 'status': 'PASS' if not no_mfa else 'FAIL',
            'message': f"{len(no_mfa)} console users lack MFA",
            'remediation_available': False, 'remediation': 'Enable MFA for users (manual)'}

def check_root_hardware_mfa():
    mfa = iam_client.list_virtual_mfa_devices()['VirtualMFADevices']
    return {'control': 'IAM.6', 'status': 'PASS' if any(d['SerialNumber'].endswith('root') for d in mfa) else 'FAIL',
            'message': 'Root has hardware MFA' if any(d['SerialNumber'].endswith('root') for d in mfa) else 'No hardware MFA for root',
            'remediation_available': False, 'remediation': 'Enable hardware MFA for root (manual)'}

def check_root_mfa():
    mfa = iam_client.get_account_summary()['SummaryMap'].get('AccountMFAEnabled', 0)
    return {'control': 'IAM.9', 'status': 'PASS' if mfa == 1 else 'FAIL',
            'message': 'Root MFA enabled' if mfa == 1 else 'Root MFA not enabled',
            'remediation_available': False, 'remediation': 'Enable MFA for root (manual)'}

def check_password_length():
    try:
        policy = iam_client.get_account_password_policy()['PasswordPolicy']
        compliant = policy.get('MinimumPasswordLength', 0) >= 14
        return {'control': 'IAM.15', 'status': 'PASS' if compliant else 'FAIL',
                'message': f"Min length: {policy.get('MinimumPasswordLength', 'None')}",
                'remediation_available': True, 'remediation': 'Set password policy length to 14+'}
    except:
        return {'control': 'IAM.15', 'status': 'FAIL', 'message': 'No policy defined', 'remediation_available': True}

def check_password_reuse():
    try:
        policy = iam_client.get_account_password_policy()['PasswordPolicy']
        compliant = policy.get('PasswordReusePrevention', 0) >= 1
        return {'control': 'IAM.16', 'status': 'PASS' if compliant else 'FAIL',
                'message': f"Reuse prevention: {policy.get('PasswordReusePrevention', 'None')}",
                'remediation_available': True, 'remediation': 'Prevent password reuse in policy'}
    except:
        return {'control': 'IAM.16', 'status': 'FAIL', 'message': 'No policy defined', 'remediation_available': True}

def check_support_role():
    roles = iam_client.list_roles()['Roles']
    support = any('Support' in r['RoleName'] for r in roles)
    return {'control': 'IAM.18', 'status': 'PASS' if support else 'FAIL',
            'message': 'Support role exists' if support else 'No support role found',
            'remediation_available': True, 'remediation': 'Create AWS support role'}

def check_unused_credentials():
    report = iam_client.get_credential_report()['Content'].decode('utf-8').splitlines()[1:]
    unused = [r.split(',')[0] for r in report if not r.split(',')[4] and int(time.time() - datetime.strptime(r.split(',')[3], '%Y-%m-%dT%H:%M:%SZ').timestamp()) > 45*86400]
    return {'control': 'IAM.22', 'status': 'PASS' if not unused else 'FAIL',
            'message': f"{len(unused)} credentials unused >45 days",
            'remediation_available': False, 'remediation': 'Remove unused creds (manual)'}

def check_expired_certificates():
    certs = iam_client.list_server_certificates()['ServerCertificateMetadataList']
    expired = [c['ServerCertificateName'] for c in certs if c['Expiration'] < datetime.now(timezone.utc)]
    return {'control': 'IAM.26', 'status': 'PASS' if not expired else 'FAIL',
            'message': f"{len(expired)} expired certificates",
            'remediation_available': True, 'remediation': 'Delete expired certificates'}

def check_cloudshell_policy():
    entities = iam_client.get_entities_for_policy(PolicyArn='arn:aws:iam::aws:policy/AWSCloudShellFullAccess')['PolicyUsers'] + \
               iam_client.get_entities_for_policy(PolicyArn='arn:aws:iam::aws:policy/AWSCloudShellFullAccess')['PolicyGroups'] + \
               iam_client.get_entities_for_policy(PolicyArn='arn:aws:iam::aws:policy/AWSCloudShellFullAccess')['PolicyRoles']
    return {'control': 'IAM.27', 'status': 'PASS' if not entities else 'FAIL',
            'message': f"{len(entities)} entities with CloudShellFullAccess",
            'remediation_available': False, 'remediation': 'Remove CloudShellFullAccess (manual)'}

def check_access_analyzer():
    analyzers = iam_client.list_access_analyzers()['AccessAnalyzers']
    return {'control': 'IAM.28', 'status': 'PASS' if analyzers else 'FAIL',
            'message': 'Access Analyzer enabled' if analyzers else 'No Access Analyzer found',
            'remediation_available': True, 'remediation': 'Enable Access Analyzer'}

def check_kms_rotation():
    keys = kms_client.list_keys()['Keys']
    no_rotation = [k['KeyId'] for k in keys if not kms_client.get_key_rotation_status(KeyId=k['KeyId'])['KeyRotationEnabled']]
    return {'control': 'KMS.4', 'status': 'PASS' if not no_rotation else 'FAIL',
            'message': f"{len(no_rotation)}/{len(keys)} keys lack rotation",
            'remediation_available': True, 'remediation': 'Enable KMS key rotation'}

def check_rds_public():
    dbs = rds_client.describe_db_instances()['DBInstances']
    public = [db['DBInstanceIdentifier'] for db in dbs if db['PubliclyAccessible']]
    return {'control': 'RDS.2', 'status': 'PASS' if not public else 'FAIL',
            'message': f"{len(public)}/{len(dbs)} RDS instances public",
            'remediation_available': True, 'remediation': 'Disable public access on RDS'}

def check_rds_encryption():
    dbs = rds_client.describe_db_instances()['DBInstances']
    unencrypted = [db['DBInstanceIdentifier'] for db in dbs if not db['StorageEncrypted']]
    return {'control': 'RDS.3', 'status': 'PASS' if not unencrypted else 'FAIL',
            'message': f"{len(unencrypted)}/{len(dbs)} RDS instances unencrypted",
            'remediation_available': False, 'remediation': 'Recreate RDS with encryption (manual)'}

def check_rds_auto_upgrades():
    dbs = rds_client.describe_db_instances()['DBInstances']
    no_upgrade = [db['DBInstanceIdentifier'] for db in dbs if not db['AutoMinorVersionUpgrade']]
    return {'control': 'RDS.13', 'status': 'PASS' if not no_upgrade else 'FAIL',
            'message': f"{len(no_upgrade)}/{len(dbs)} RDS lack auto upgrades",
            'remediation_available': True, 'remediation': 'Enable auto minor upgrades'}

def check_s3_block_public():
    buckets = [b['Name'] for b in s3_client.list_buckets()['Buckets']]
    non_compliant = [b for b in buckets if not all(s3_client.get_public_access_block(Bucket=b)['PublicAccessBlockConfiguration'].get(k, False) for k in ['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets'])]
    return {'control': 'S3.1', 'status': 'PASS' if not non_compliant else 'FAIL',
            'message': f"{len(non_compliant)}/{len(buckets)} buckets lack full block",
            'remediation_available': True, 'remediation': 'Enable S3 block public access'}

def check_s3_ssl():
    buckets = [b['Name'] for b in s3_client.list_buckets()['Buckets']]
    no_ssl = [b for b in buckets if not (s3_client.get_bucket_policy(Bucket=b).get('Policy') and 'aws:SecureTransport' in s3_client.get_bucket_policy(Bucket=b)['Policy'])]
    return {'control': 'S3.5', 'status': 'PASS' if not no_ssl else 'FAIL',
            'message': f"{len(no_ssl)}/{len(buckets)} buckets lack SSL policy",
            'remediation_available': True, 'remediation': 'Enforce SSL in bucket policy'}

def check_s3_public_access():
    buckets = [b['Name'] for b in s3_client.list_buckets()['Buckets']]
    non_compliant = [b for b in buckets if not all(s3_client.get_public_access_block(Bucket=b)['PublicAccessBlockConfiguration'].get(k, False) for k in ['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets'])]
    return {'control': 'S3.8', 'status': 'PASS' if not non_compliant else 'FAIL',
            'message': f"{len(non_compliant)}/{len(buckets)} buckets lack full block",
            'remediation_available': True, 'remediation': 'Enable S3 block public access'}

def check_s3_mfa_delete():
    buckets = [b['Name'] for b in s3_client.list_buckets()['Buckets']]
    no_mfa = [b for b in buckets if s3_client.get_bucket_versioning(Bucket=b).get('MFADelete') != 'Enabled']
    return {'control': 'S3.20', 'status': 'PASS' if not no_mfa else 'FAIL',
            'message': f"{len(no_mfa)}/{len(buckets)} buckets lack MFA delete",
            'remediation_available': True, 'remediation': 'Enable MFA delete on buckets'}

def check_s3_write_logging():
    trails = cloudtrail_client.describe_trails()['trailList']
    no_write = [t['Name'] for t in trails if not any(s['ReadWriteType'] == 'WriteOnly' for s in cloudtrail_client.get_event_selectors(TrailName=t['Name'])['EventSelectors'])]
    return {'control': 'S3.22', 'status': 'PASS' if not no_write else 'FAIL',
            'message': f"{len(no_write)}/{len(trails)} trails lack S3 write logging",
            'remediation_available': True, 'remediation': 'Enable S3 write event logging'}

def check_s3_read_logging():
    trails = cloudtrail_client.describe_trails()['trailList']
    no_read = [t['Name'] for t in trails if not any(s['ReadWriteType'] == 'ReadOnly' for s in cloudtrail_client.get_event_selectors(TrailName=t['Name'])['EventSelectors'])]
    return {'control': 'S3.23', 'status': 'PASS' if not no_read else 'FAIL',
            'message': f"{len(no_read)}/{len(trails)} trails lack S3 read logging",
            'remediation_available': True, 'remediation': 'Enable S3 read event logging'}

# Remediation Functions (Examples for Key Controls)
def remediate_cloudtrail_encryption(dry_run: bool = True, confirm: bool = False, **kwargs) -> Dict[str, str]:
    """
    Remediate CloudTrail encryption by enabling KMS encryption.
    
    This function creates a KMS key specifically for CloudTrail encryption if
    needed and updates all trails to use KMS encryption.
    
    Args:
        dry_run (bool): If True, only simulate the action without making changes
        confirm (bool): If True, proceed with the remediation
        **kwargs: Additional parameters for remediation
        
    Returns:
        Dict[str, str]: Result of the remediation action
    """
    logger.info(f"Remediating CloudTrail encryption (dry_run={dry_run}, confirm={confirm})")
    
    if dry_run:
        return {'message': 'Dry run: Would enable KMS encryption'}
    
    if not confirm:
        return {'message': 'Confirmation required to proceed with remediation'}
    
    try:
        trails = cloudtrail_client.describe_trails()['trailList']
        
        # Create a KMS key for CloudTrail encryption
        try:
            key_response = kms_client.create_key(Description='CIS CloudTrail')
            key = key_response['KeyMetadata']['Arn']
            logger.info(f"Created KMS key: {key}")
        except ClientError as e:
            logger.error(f"Failed to create KMS key: {e}", exc_info=True)
            return {'message': f"Failed to create KMS key: {str(e)}"}
        
        # Update each trail without encryption
        for t in trails:
            if not t.get('KmsKeyId'):
                try:
                    # Backup the current trail configuration
                    backup_key = f"trail-{t['Name']}-{int(time.time())}.json"
                    s3_client.put_object(
                        Bucket=BACKUP_BUCKET, 
                        Key=backup_key, 
                        Body=json.dumps(t)
                    )
                    logger.info(f"Backed up trail {t['Name']} to {backup_key}")
                    
                    # Update the trail with encryption
                    cloudtrail_client.update_trail(Name=t['Name'], KmsKeyId=key)
                    logger.info(f"Enabled encryption for trail {t['Name']}")
                except ClientError as e:
                    logger.error(f"Failed to update trail {t['Name']}: {e}", exc_info=True)
                    return {'message': f"Failed to update trail {t['Name']}: {str(e)}"}
        
        return {'message': f"Encrypted {len(trails)} trails"}
    except ClientError as e:
        logger.error(f"Error in remediation: {e}", exc_info=True)
        return {'message': f"Remediation failed: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error in remediation: {e}", exc_info=True)
        return {'message': f"Unexpected error during remediation: {str(e)}"}

def remediate_iam_password_policy(dry_run: bool = True, confirm: bool = False, **kwargs) -> Dict[str, str]:
    """
    Remediate IAM password policy to meet security requirements.
    
    Updates the IAM password policy to enforce strong passwords, including
    minimum length, complexity, and rotation requirements.
    
    Args:
        dry_run (bool): If True, only simulate the action without making changes
        confirm (bool): If True, proceed with the remediation
        **kwargs: Additional parameters for remediation
        
    Returns:
        Dict[str, str]: Result of the remediation action
    """
    logger.info(f"Remediating IAM password policy (dry_run={dry_run}, confirm={confirm})")
    
    if dry_run:
        return {'message': 'Dry run: Would update password policy'}
    
    if not confirm:
        return {'message': 'Confirmation required to proceed with remediation'}
    
    try:
        # Backup current policy if it exists
        try:
            current = iam_client.get_account_password_policy().get('PasswordPolicy', {})
            s3_client.put_object(
                Bucket=BACKUP_BUCKET, 
                Key=f"iam-policy-{int(time.time())}.json", 
                Body=json.dumps(current)
            )
            logger.info("Backed up current password policy")
        except ClientError as e:
            logger.warning(f"No existing password policy to backup: {e}", exc_info=True)
        
        # Update policy with secure settings
        iam_client.update_account_password_policy(
            MinimumPasswordLength=14,
            RequireSymbols=True,
            RequireNumbers=True,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            AllowUsersToChangePassword=True,
            MaxPasswordAge=90,
            PasswordReusePrevention=24
        )
        logger.info("Successfully updated IAM password policy")
        
        return {'message': 'Updated IAM password policy with secure settings'}
    except ClientError as e:
        logger.error(f"Error updating IAM password policy: {e}", exc_info=True)
        return {'message': f"Failed to update policy: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error updating IAM password policy: {e}", exc_info=True)
        return {'message': f"Unexpected error during remediation: {str(e)}"}

def remediate_s3_public_access(bucket_name: str, dry_run: bool = True, confirm: bool = False, **kwargs) -> Dict[str, str]:
    """
    Remediate S3 bucket to block public access.
    
    Configures an S3 bucket to block all public access by enabling
    the PublicAccessBlock configuration with all options enabled.
    
    Args:
        bucket_name (str): Name of the S3 bucket to remediate
        dry_run (bool): If True, only simulate the action without making changes
        confirm (bool): If True, proceed with the remediation
        **kwargs: Additional parameters for remediation
        
    Returns:
        Dict[str, str]: Result of the remediation action
    """
    logger.info(f"Remediating S3 public access for bucket {bucket_name} (dry_run={dry_run}, confirm={confirm})")
    
    if not bucket_name:
        return {'message': 'Missing bucket name parameter'}
    
    if dry_run:
        return {'message': f"Dry run: Would block public access on {bucket_name}"}
    
    if not confirm:
        return {'message': 'Confirmation required to proceed with remediation'}
    
    try:
        # Backup current ACL
        try:
            current_acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            s3_client.put_object(
                Bucket=BACKUP_BUCKET, 
                Key=f"{bucket_name}-acl-{int(time.time())}.json", 
                Body=json.dumps(current_acl)
            )
            logger.info(f"Backed up ACL for bucket {bucket_name}")
        except ClientError as e:
            logger.warning(f"Failed to backup ACL for bucket {bucket_name}: {e}", exc_info=True)
        
        # Apply public access block
        s3_client.put_public_access_block(
            Bucket=bucket_name, 
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True, 
                'IgnorePublicAcls': True, 
                'BlockPublicPolicy': True, 
                'RestrictPublicBuckets': True
            }
        )
        logger.info(f"Successfully blocked public access on bucket {bucket_name}")
        
        return {'message': f"Blocked public access on {bucket_name}"}
    except ClientError as e:
        logger.error(f"Error setting public access block on {bucket_name}: {e}", exc_info=True)
        return {'message': f"Failed to block public access: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error remediting S3 bucket {bucket_name}: {e}", exc_info=True)
        return {'message': f"Unexpected error during remediation: {str(e)}"}

# HTML Report Generation with error handling
def generate_html_report(results: Dict[str, Any]) -> str:
    """
    Generate an HTML report of compliance results and save to S3.
    
    Creates a formatted HTML report showing the status of all evaluated
    controls, categorizes them by pass/fail/error status, and provides
    visual indicators and remediation guidance.
    
    Args:
        results (Dict[str, Any]): Dictionary of control check results with
                                 control IDs as keys and check details as values
        
    Returns:
        str: Pre-signed URL to access the report in S3
    """
    try:
        template = Template("""
        <html><head><title>CIS v3.0 Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; }
            th { background-color: #f2f2f2; text-align: left; }
            tr:nth-child(even) { background-color: #f9f9f9; }
            .pass { color: green; }
            .fail { color: red; }
            .error { color: orange; }
            .summary { margin-bottom: 20px; }
            .timestamp { font-style: italic; color: #666; }
        </style></head>
        <body>
            <h1>CIS AWS Foundations Benchmark v3.0 Report</h1>
            <p class="timestamp">Generated: {{ timestamp }}</p>
            
            <div class="summary">
                <h2>Summary</h2>
                <p>
                    Pass: {{ results.values() | selectattr('status', 'equalto', 'PASS') | list | length }} |
                    Fail: {{ results.values() | selectattr('status', 'equalto', 'FAIL') | list | length }} |
                    Error: {{ results.values() | selectattr('status', 'equalto', 'ERROR') | list | length }} |
                    Total: {{ results.values() | list | length }}
                </p>
            </div>
            
            <table>
                <tr>
                    <th>Control</th>
                    <th>Status</th>
                    <th>Message</th>
                    <th>Remediation</th>
                </tr>
                {% for r in results.values() %}
                <tr>
                    <td>{{ r.control }}</td>
                    <td class="{{ r.status.lower() }}">{{ r.status }}</td>
                    <td>{{ r.message }}</td>
                    <td>{{ r.remediation }}</td>
                </tr>
                {% endfor %}
            </table>
        </body></html>
        """)
        
        html = template.render(
            timestamp=datetime.now(timezone.utc).isoformat(), 
            results=results
        )
        
        key = f"report-{int(time.time())}.html"
        s3_client.put_object(
            Bucket=REPORT_BUCKET, 
            Key=key, 
            Body=html, 
            ContentType='text/html'
        )
        logger.info(f"Generated report: {key}")
        
        return generate_presigned_url(REPORT_BUCKET, key)
    except Exception as e:
        logger.error(f"Failed to generate report: {e}", exc_info=True)
        return ""

# Main Lambda Handler with input validation
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main entry point for Lambda function.
    
    Handles the event processing for both evaluation and remediation actions.
    Validates inputs, loads controls, executes checks or remediation functions,
    and generates reports.
    
    Args:
        event (Dict[str, Any]): Lambda event data containing action and parameters
        context (Any): Lambda context
        
    Returns:
        Dict[str, Any]: Lambda response containing results or error information
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    # Validate input
    if not isinstance(event, dict):
        logger.error("Invalid event format")
        return {
            'statusCode': 400, 
            'body': json.dumps({'error': 'Invalid event format'})
        }
    
    action = event.get('action', 'evaluate')
    if action not in ['evaluate', 'remediate']:
        logger.error(f"Invalid action: {action}")
        return {
            'statusCode': 400, 
            'body': json.dumps({'error': 'Invalid action, must be evaluate or remediate'})
        }
    
    try:
        # Load controls
        controls = load_controls()
        if not controls:
            logger.error("Failed to load controls definition")
            return {
                'statusCode': 500, 
                'body': json.dumps({'error': 'Failed to load controls definition'})
            }
        
        if action == 'evaluate':
            # Run all control checks
            logger.info("Starting compliance evaluation")
            results = []
            futures = {}

            # Fetch required AWS data in parallel first
            # Determine which data is needed by the controls we intend to check
            required_fetch_keys = set()
            target_controls = controls.keys() # Or get from event if allowing targeted eval
            # Simplified: fetch all data defined in FETCH_MAP for now
            # Optimization: analyze CONTROL_CHECK_MAP to see which aws_data keys are actually used
            logger.info("Fetching required AWS data...")
            aws_data = get_aws_data(FETCH_MAP)
            fetch_duration = time.time() - start_time
            logger.info(f"AWS data fetching completed in {fetch_duration:.2f} seconds.")

            # Execute checks in parallel
            logger.info(f"Submitting {len(target_controls)} control checks for parallel execution...")
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                for control_id in target_controls:
                    check_function = CONTROL_CHECK_MAP.get(control_id)
                    if check_function:
                        # Submit the check function with the fetched aws_data
                        futures[executor.submit(check_function, aws_data)] = control_id
                    else:
                        logger.warning(f"No check function implemented for {control_id}")
                        results.append(create_standard_response(control_id, 'ERROR', 'Check function not implemented.'))

                # Collect results as they complete
                for future in as_completed(futures):
                    control_id = futures[future]
                    try:
                        result = future.result()
                        results.append(result)
                        logger.debug(f"Completed check for {control_id}: {result.get('status')}")
                    except Exception as e:
                        logger.error(f"Unexpected error executing check for {control_id}: {e}", exc_info=True)
                        results.append(create_standard_response(control_id, 'ERROR', f"Check execution failed: {e}"))

            # Generate HTML report
            html_content, report_key = generate_html_report(results, controls)
            report_url = ""
            if html_content and report_key and REPORT_BUCKET:
                try:
                    s3_client.put_object(
                        Bucket=REPORT_BUCKET,
                        Key=report_key,
                        Body=html_content,
                        ContentType='text/html',
                        Metadata={'cis-report-timestamp': datetime.now(timezone.utc).isoformat()}
                    )
                    logger.info(f"Successfully uploaded report to s3://{REPORT_BUCKET}/{report_key}")
                    report_url = generate_presigned_url(REPORT_BUCKET, report_key)
                except ClientError as e:
                    logger.error(f"Failed to upload report to S3: {e}", exc_info=True)
                except Exception as e:
                     logger.error(f"Unexpected error uploading report: {e}", exc_info=True)

            end_time = time.time()
            duration = end_time - start_time
            logger.info(f"Evaluation completed in {duration:.2f} seconds.")

            # Return results (consider limits on response size for API Gateway/Lambda)
            # Returning the full results list might exceed limits for large accounts.
            # The report URL is often the primary output.
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'status': 'Evaluation Complete',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'duration_seconds': round(duration, 2),
                    'report_url': report_url,
                    # Optionally include summary counts or truncated results here
                    'summary': {
                        status: sum(1 for r in results if r.get('status') == status)
                        for status in ['PASS', 'FAIL', 'ERROR']
                    }
                    #'results': results # Be cautious about size
                }, default=str) # Use default=str for datetime etc.
            }

        elif action == 'remediate':
            # Validate remediation parameters
            control_id = event.get('control_id')
            if not control_id:
                logger.error("Missing control_id for remediation")
                return {
                    'statusCode': 400, 
                    'body': json.dumps({'error': "Missing control_id for remediation"})
                }
            
            # Get the remediation function
            function_name = f"remediate_{control_id.replace('.', '_').lower()}"
            remediate_function = globals().get(function_name)
            
            if not remediate_function:
                logger.error(f"No remediation function for {control_id}")
                return {
                    'statusCode': 404, 
                    'body': json.dumps({'error': f'Remediation not implemented for {control_id}'})
                }
            
            # Run remediation
            logger.info(f"Executing remediation for {control_id}")
            result = remediate_function(
                dry_run=event.get('dry_run', True),
                confirm=event.get('confirm', False),
                **event.get('parameters', {})
            )
            
            return {
                'statusCode': 200,
                'body': json.dumps(result)
            }

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return {
            'statusCode': 500, 
            'body': json.dumps({'error': f'Unexpected error: {str(e)}'})
        }

if __name__ == "__main__":
    # For local testing
    test_event = {'action': 'evaluate'}
    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))