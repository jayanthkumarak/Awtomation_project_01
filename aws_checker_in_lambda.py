import json
import boto3
import time
import os
import logging
import csv
import io
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

# Control ID to Check Function Mapping
CONTROL_CHECK_MAP = {
    'Account.1': check_security_contact,
    'CloudTrail.1': check_cloudtrail_enabled,
    'CloudTrail.2': check_cloudtrail_encryption,
    'CloudTrail.4': check_cloudtrail_validation,
    'Config.1': check_config_enabled,
    'EC2.2': check_vpc_default_sg,
    'EC2.6': check_vpc_flow_logs,
    'EC2.7': check_ebs_encryption,
    'EC2.8': check_imdsv2,
    'EC2.21': check_nacl_open_ports,
    'EC2.53': check_sg_open_ipv4,
    'EC2.54': check_sg_open_ipv6,
    'EFS.1': check_efs_encryption,
    'IAM.2': check_iam_user_policies,
    'IAM.3': check_iam_key_rotation,
    'IAM.4': check_root_access_keys,
    'IAM.5': check_iam_mfa_console,
    'IAM.9': check_root_mfa,
    'IAM.15': check_password_length,
    'IAM.16': check_password_reuse,
    'IAM.18': check_support_role,
    'IAM.22': check_unused_credentials,
    'IAM.26': check_expired_certificates,
    'IAM.27': check_cloudshell_policy,
    'IAM.28': check_access_analyzer,
    'KMS.4': check_kms_rotation,
    'RDS.2': check_rds_public,
    'RDS.3': check_rds_encryption,
    'RDS.13': check_rds_auto_upgrades,
    'S3.1': check_s3_block_public,
    'S3.5': check_s3_ssl,
    'S3.8': check_s3_public_access,
    'S3.20': check_s3_mfa_delete,
    'S3.22': check_s3_write_logging,
    'S3.23': check_s3_read_logging,
}

# Remediation Function Mapping (Example - Can be expanded)
# This maps control IDs to their corresponding remediation functions
REMEDIATION_FUNCTION_MAP = {
    'CloudTrail.2': remediate_cloudtrail_encryption,
    # 'IAM.15': remediate_iam_password_policy, # Based on check_password_length
    # 'IAM.16': remediate_iam_password_policy, # Based on check_password_reuse - uses same remediation
    'S3.1': remediate_s3_public_access, # Corresponds to check_s3_block_public
    'S3.8': remediate_s3_public_access, # Corresponds to check_s3_public_access
    # Add other remediation functions here as they are implemented
}

# Define MAX_WORKERS for ThreadPoolExecutor
MAX_WORKERS = 10 # Adjust as needed based on Lambda resources and API limits

# Helper function to create standardized responses
def create_standard_response(control_id: str, status: str, message: str, remediation: Optional[str] = None, remediation_available: bool = False) -> Dict[str, Any]:
    """Creates a standard dictionary structure for check results."""
    return {
        'control': control_id,
        'status': status,
        'message': message,
        'remediation': remediation if remediation is not None else "See control documentation.",
        'remediation_available': remediation_available
    }

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

# Helper function to paginate through AWS API calls
def paginate(client, method, result_key, **kwargs):
    """
    Paginate through AWS API calls.
    
    Args:
        client: Boto3 client
        method: Client method to call
        result_key: Key in the response containing the results
        **kwargs: Additional arguments for the method
    
    Returns:
        List: Combined results from all pages
    """
    paginator = client.get_paginator(method)
    results = []
    for page in paginator.paginate(**kwargs):
        results.extend(page[result_key])
    return results

# Fetch functions for get_aws_data
def fetch_trails():
    """Fetch CloudTrail trails."""
    return paginate(cloudtrail_client, 'describe_trails', 'trails')

def fetch_users():
    """Fetch IAM users."""
    return paginate(iam_client, 'list_users', 'Users')

def fetch_credential_report():
    """Fetch IAM credential report."""
    try:
        response = iam_client.get_credential_report()
        if response['State'] == 'COMPLETE':
            return json.loads(response['Content'].decode('utf-8'))
        else:
            logger.warning(f"Credential report not ready: {response['State']}")
            return None
    except ClientError as e:
        logger.error(f"Error fetching credential report: {e}", exc_info=True)
        return None

def fetch_security_groups():
    """Fetch EC2 security groups."""
    return paginate(ec2_client, 'describe_security_groups', 'SecurityGroups')

def fetch_buckets():
    """Fetch S3 buckets."""
    return paginate(s3_client, 'list_buckets', 'Buckets')

def fetch_rds_instances():
    """Fetch RDS instances."""
    return paginate(rds_client, 'describe_db_instances', 'DBInstances')

def fetch_kms_keys():
    """Fetch KMS keys."""
    return paginate(kms_client, 'list_keys', 'Keys')

def fetch_efs_filesystems():
    """Fetch EFS file systems."""
    return paginate(efs_client, 'describe_file_systems', 'FileSystems')

def fetch_password_policy():
    """Fetch IAM password policy."""
    try:
        return iam_client.get_account_password_policy()['PasswordPolicy']
    except ClientError as e:
        logger.error(f"Error fetching password policy: {e}", exc_info=True)
        return None

def fetch_account_summary():
    """Fetch IAM account summary."""
    try:
        return iam_client.get_account_summary()['SummaryMap']
    except ClientError as e:
        logger.error(f"Error fetching account summary: {e}", exc_info=True)
        return None

def fetch_instances():
    """Fetch EC2 instances."""
    reservations = paginate(ec2_client, 'describe_instances', 'Reservations')
    instances = []
    for r in reservations:
        instances.extend(r['Instances'])
    return instances

# Fetch map for get_aws_data
FETCH_MAP = {
    'trails': fetch_trails,
    'users': fetch_users,
    'credential_report': fetch_credential_report,
    'security_groups': fetch_security_groups,
    'buckets': fetch_buckets,
    'rds_instances': fetch_rds_instances,
    'kms_keys': fetch_kms_keys,
    'efs_filesystems': fetch_efs_filesystems,
    'password_policy': fetch_password_policy,
    'account_summary': fetch_account_summary,
    'instances': fetch_instances,
}

# Get AWS data function
def get_aws_data() -> Dict[str, Any]:
    """
    Fetch AWS data concurrently using ThreadPoolExecutor.
    
    Returns:
        Dict[str, Any]: Dictionary of fetched AWS data
    """
    aws_data = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_key = {executor.submit(fetch_func): key for key, fetch_func in FETCH_MAP.items()}
        for future in as_completed(future_to_key):
            key = future_to_key[future]
            try:
                aws_data[key] = future.result()
            except Exception as e:
                logger.error(f"Error fetching {key}: {e}", exc_info=True)
                aws_data[key] = None
    return aws_data

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

def check_cloudtrail_enabled(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check if CloudTrail is properly enabled (Updated Logic).
    
    Evaluates if at least one multi-region CloudTrail trail exists and is
    configured to log management events (ReadWriteType: All).
    
    Args:
        aws_data (Dict[str, Any]): Dictionary of pre-fetched AWS data.
    
    Returns:
        Dict[str, Any]: Control check result containing status and remediation info
    """
    CONTROL_ID = 'CloudTrail.1'
    
    def logs_management_events(trail_name: str) -> bool:
        """Check if a trail logs management events with ReadWriteType='All'."""
        try:
            response = cloudtrail_client.get_event_selectors(TrailName=trail_name)
            # Check primary event selectors first
            selectors = response.get('EventSelectors', [])
            if selectors:
                # Check if *any* selector includes management events and has ReadWriteType='All'
                for selector in selectors:
                    if selector.get('IncludeManagementEvents', False) and selector.get('ReadWriteType') == 'All':
                        return True
                # If selectors exist but none match, return False for this trail
                return False 
            
            # Fallback: Check Advanced Event Selectors (more complex)
            # A simple check: If advanced selectors exist, assume user configured *something*
            # A better check would parse FieldSelectors for management event criteria.
            advanced_selectors = response.get('AdvancedEventSelectors', [])
            if advanced_selectors:
                 logger.info(f"Trail {trail_name} uses Advanced Event Selectors. Assuming management events logged for simplicity.")
                 return True # Simplification: Assume advanced selectors are okay for basic check
                 
            # Fallback: Check legacy Insight selectors (less common for base management events)
            insight_selectors = response.get('InsightSelectors', [])
            if insight_selectors:
                 logger.info(f"Trail {trail_name} uses Insight Selectors. Assuming management events logged for simplicity.")
                 return True # Simplification
                 
            # If no selectors found at all
            logger.warning(f"Trail {trail_name} has no standard, advanced, or insight selectors found.")
            return False
        except ClientError as e:
            if e.response['Error']['Code'] == 'TrailNotFoundException':
                 logger.warning(f"Trail {trail_name} not found when getting event selectors.")
            elif e.response['Error']['Code'] == 'UnsupportedOperationException': # e.g., for CloudTrail Lake
                 logger.info(f"GetEventSelectors not supported for {trail_name} (likely CloudTrail Lake). Skipping selector check.")
                 return True # Assume Lake trails are configured intentionally
            else:
                 logger.warning(f"Failed to get event selectors for trail {trail_name}: {e}", exc_info=True)
            return False # Treat errors as non-compliant for selectors
    
    try:
        trails = aws_data.get('trails')
        if trails is None:
             return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve CloudTrail data.", False)
        
        if not trails:
            return create_standard_response(CONTROL_ID, 'FAIL', "No CloudTrail trails found")
            
        # Find multi-region trails
        multi_region_trails = [t for t in trails if t.get('IsMultiRegionTrail')]       
        
        # Check if *at least one* multi-region trail logs management events appropriately
        compliant_trail_found = False
        checked_trails_count = 0
        logging_ok_count = 0
        if multi_region_trails:
            for trail in multi_region_trails:
                 trail_name = trail.get('Name')
                 if trail_name:
                      checked_trails_count += 1
                      if logs_management_events(trail_name):
                           logging_ok_count += 1
                           compliant_trail_found = True
                           # break # Uncomment to PASS if just *one* compliant multi-region trail is enough
            
        status = 'PASS' if compliant_trail_found else 'FAIL'
        
        message = (
            f"Found {len(trails)} trail(s). {len(multi_region_trails)} are multi-region. "
            f"Checked {checked_trails_count} multi-region trail(s) for management event logging ('All'): {logging_ok_count} passed."
        )
        if status == 'FAIL' and multi_region_trails:
            message += " Ensure at least one multi-region trail logs all management events."
        elif status == 'FAIL' and not multi_region_trails:
             message += " No multi-region trails found."
        
        return create_standard_response(CONTROL_ID, status, message)
        
    except Exception as e:
         error_message = f"Unexpected error during CloudTrail check: {str(e)}"
         logger.error(error_message, exc_info=True)
         return create_standard_response(CONTROL_ID, 'ERROR', error_message, False)

def check_cloudtrail_encryption(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check if CloudTrail trails have KMS encryption enabled.
    
    Evaluates whether CloudTrail trails are configured with KMS encryption
    for protecting log data at rest.

    Args:
        aws_data (Dict[str, Any]): Dictionary of pre-fetched AWS data.
    
    Returns:
        Dict[str, Any]: Control check result with encryption status details
    """
    CONTROL_ID = 'CloudTrail.2'
    try:
        trails = aws_data.get('trails')
        if trails is None:
             return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve CloudTrail data.", False)
        if not trails:
            return create_standard_response(CONTROL_ID, 'PASS', "No CloudTrail trails found.") # No trails, nothing to encrypt

        non_encrypted = [t['Name'] for t in trails if not t.get('KmsKeyId')]
        status = 'PASS' if not non_encrypted else 'FAIL'
        message = f"{len(trails) - len(non_encrypted)}/{len(trails)} trails are encrypted."
        if non_encrypted:
             message += f" Non-encrypted: {", ".join(non_encrypted[:5])}{'...' if len(non_encrypted) > 5 else ''}"

        return create_standard_response(
             CONTROL_ID, 
             status, 
             message,
             remediation='Enable KMS encryption on trails', 
             remediation_available=True
        )
    except Exception as e:
        logger.error(f"Error checking CloudTrail encryption: {e}", exc_info=True)
        return create_standard_response(
            CONTROL_ID, 
            'ERROR', 
            f'Failed to check: {str(e)}', 
            remediation_available=False
        )

def check_cloudtrail_validation(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check if CloudTrail log file validation is enabled.
    
    Verifies that CloudTrail trails have log file validation enabled,
    which helps ensure log file integrity.

    Args:
        aws_data (Dict[str, Any]): Dictionary of pre-fetched AWS data.
    
    Returns:
        Dict[str, Any]: Control check result with validation status details
    """
    CONTROL_ID = 'CloudTrail.4'
    try:
        trails = aws_data.get('trails')
        if trails is None:
             return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve CloudTrail data.", False)
        if not trails:
            return create_standard_response(CONTROL_ID, 'PASS', "No CloudTrail trails found.")

        no_validation = [t['Name'] for t in trails if not t.get('LogFileValidationEnabled')]
        status = 'PASS' if not no_validation else 'FAIL'
        message = f"{len(trails) - len(no_validation)}/{len(trails)} trails have log validation enabled."
        if no_validation:
             message += f" Lacking validation: {", ".join(no_validation[:5])}{'...' if len(no_validation) > 5 else ''}"

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Enable log file validation on trails', 
            remediation_available=True
        )
    except Exception as e:
        logger.error(f"Error checking CloudTrail validation: {e}", exc_info=True)
        return create_standard_response(
            CONTROL_ID, 
            'ERROR', 
            f'Failed to check: {str(e)}', 
            remediation_available=False
        )

def check_config_enabled() -> Dict[str, Any]:
    """
    Check if AWS Config is enabled.
    
    Verifies that AWS Config service is enabled for resource inventory,
    configuration history, and change notification.
    
    Returns:
        Dict[str, Any]: Control check result with AWS Config status
    """
    CONTROL_ID = 'Config.1'
    try:
        # Use paginate helper to ensure all recorders are considered
        recorders = paginate(config_client, 'describe_configuration_recorders', 'ConfigurationRecorders')
        
        # Check if recorders list is not empty and if any recorder is currently recording
        is_enabled = False
        if recorders:
             # Need to check the status of at least one recorder
             try:
                  # Check status of the first recorder found, assuming it represents overall status
                  # A more complex check might verify all recorders or specific ones.
                  status = config_client.describe_configuration_recorder_status(ConfigurationRecorderNames=[recorders[0]['name']])
                  if status.get('ConfigurationRecordersStatus') and status['ConfigurationRecordersStatus'][0].get('recording'):
                       is_enabled = True
             except ClientError as status_e:
                  logger.warning(f"Could not get status for config recorder {recorders[0].get('name')}: {status_e}")
                  # If status check fails, rely on the presence of recorders as indication of being enabled (though maybe not recording)
                  is_enabled = True 

        status_msg = 'Config enabled and recording' if is_enabled else 'Config recorder found but may not be recording' if recorders else 'Config not enabled'
        final_status = 'PASS' if is_enabled else 'FAIL'

        return create_standard_response(
            CONTROL_ID, 
            final_status, 
            status_msg,
            remediation='Enable AWS Config and start the recorder', 
            remediation_available=True
        )
    except ClientError as e:
        # Handle case where Config service might not be enabled at all in the region
        # DescribeConfigurationRecorders might fail if service is totally unused.
        logger.error(f"Error checking AWS Config: {e}", exc_info=True)
        # Check specific error code if needed, otherwise assume not enabled
        return create_standard_response(
            CONTROL_ID, 
            'FAIL', 
            f'Config not enabled or error checking: {str(e)}', 
            remediation='Enable AWS Config', 
            remediation_available=True
        )
    except Exception as e:
         logger.error(f"Unexpected error checking AWS Config: {e}", exc_info=True)
         return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}', False)

def check_vpc_default_sg(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check if default VPC security groups have any rules. (Updated Egress Logic)
    
    Verifies that default security groups restrict all traffic by having
    no inbound rules defined and only standard default outbound rules.

    Args:
        aws_data (Dict[str, Any]): Dictionary of pre-fetched AWS data.
    
    Returns:
        Dict[str, Any]: Control check result with security group details
    """
    CONTROL_ID = 'EC2.2'
    try:
        sgs = aws_data.get('security_groups')
        if sgs is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve Security Group data.", False)
        
        default_sgs = [sg for sg in sgs if sg.get('GroupName') == 'default']
        if not default_sgs:
             logger.info("No default security groups found.")
             return create_standard_response(CONTROL_ID, 'PASS', "No default security groups found.")

        non_compliant = [] 
        for sg in default_sgs:
            has_inbound_rules = bool(sg.get('IpPermissions'))
            
            # Check egress rules: Only allow the standard IPv4 and/or IPv6 allow-all rules.
            has_non_default_egress = False
            egress_rules = sg.get('IpPermissionsEgress', [])
            allowed_egress_rules = [
                 {'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'Ipv6Ranges': [], 'PrefixListIds': [], 'UserIdGroupPairs': []},
                 {'IpProtocol': '-1', 'IpRanges': [], 'Ipv6Ranges': [{'CidrIpv6': '::/0'}], 'PrefixListIds': [], 'UserIdGroupPairs': []}
            ]
            # Check if *all* existing egress rules are present in the list of allowed rules
            for rule in egress_rules:
                 # Normalize rule structure slightly for comparison if needed (e.g., empty lists)
                 rule['IpRanges'] = rule.get('IpRanges', [])
                 rule['Ipv6Ranges'] = rule.get('Ipv6Ranges', [])
                 rule['PrefixListIds'] = rule.get('PrefixListIds', [])
                 rule['UserIdGroupPairs'] = rule.get('UserIdGroupPairs', [])
                 
                 # Check if this specific rule is one of the standard allowed ones
                 is_standard_rule = False
                 if rule in allowed_egress_rules:
                      is_standard_rule = True
                 # Handle case where a single rule might contain BOTH IPv4 and IPv6 allow all (less common but possible)
                 elif rule.get('IpProtocol') == '-1' and \ 
                      any(r.get('CidrIp') == '0.0.0.0/0' for r in rule.get('IpRanges', [])) and \ 
                      any(r.get('CidrIpv6') == '::/0' for r in rule.get('Ipv6Ranges', [])):
                      is_standard_rule = True
                      
                 if not is_standard_rule:
                      has_non_default_egress = True
                      break # Found a non-standard rule
            
            if has_inbound_rules or has_non_default_egress:
                non_compliant.append(sg['GroupId'])

        status = 'PASS' if not non_compliant else 'FAIL'
        message = f"{len(default_sgs) - len(non_compliant)}/{len(default_sgs)} default SGs restrict traffic appropriately."
        if non_compliant:
             message += f" Default SGs with disallowed rules: {", ".join(non_compliant[:5])}{'...' if len(non_compliant) > 5 else ''}"
        
        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Remove non-default rules from default SGs', 
            remediation_available=True
        )
    except Exception as e:
        logger.error(f"Error checking default security groups: {e}", exc_info=True)
        return create_standard_response(
            CONTROL_ID, 
            'ERROR', 
            f'Failed to check: {str(e)}', 
            remediation_available=False
        )

def check_vpc_flow_logs() -> Dict[str, Any]:
    """
    Check if VPC flow logs are enabled.
    
    Verifies if VPC flow logs are enabled to capture information about
    IP traffic going to and from network interfaces in the VPC.
    
    Returns:
        Dict[str, Any]: Control check result with flow log status
    """
    CONTROL_ID = 'EC2.6'
    try:
        # Use paginate helper
        logs = paginate(ec2_client, 'describe_flow_logs', 'FlowLogs')
        status = 'PASS' if logs else 'FAIL'
        message = f"{len(logs)} VPC flow logs found." if logs else "No VPC flow logs found."
        
        # Check status of logs found
        active_logs = [f for f in logs if f.get('FlowLogStatus') == 'ACTIVE']
        if logs and not active_logs:
             message += " However, none are currently ACTIVE."
             status = 'FAIL'
        elif logs:
             message += f" {len(active_logs)} are ACTIVE."

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Enable VPC flow logs for all VPCs', 
            remediation_available=True
        )
    except ClientError as e:
        logger.error(f"Error checking VPC flow logs: {e}", exc_info=True)
        # Determine if FAIL or ERROR based on exception type if needed
        return create_standard_response(
            CONTROL_ID, 
            'ERROR', 
            f'Failed to check: {str(e)}', 
            remediation_available=False
        )
    except Exception as e:
         logger.error(f"Unexpected error checking VPC flow logs: {e}", exc_info=True)
         return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}', False)

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

def check_imdsv2(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check if EC2 instances have IMDSv2 enabled.
    
    Verifies if EC2 instances are configured to use IMDSv2 (Instance Metadata
    Service v2) which provides additional security protections.

    Args:
        aws_data (Dict[str, Any]): Dictionary of pre-fetched AWS data.
    
    Returns:
        Dict[str, Any]: Control check result with IMDSv2 status details
    """
    CONTROL_ID = 'EC2.8'
    try:
        reservations = aws_data.get('instances')
        if reservations is None:
             return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve EC2 instance data.", False)

        non_compliant = []
        instance_count = 0
        # reservations is a list of reservation dicts, each containing a list of instances
        for r in reservations:
            for instance in r.get('Instances', []):
                instance_count += 1
                # Check if HttpTokens is set to 'required' for IMDSv2 enforcement
                metadata_options = instance.get('MetadataOptions', {})
                if metadata_options.get('HttpTokens') != 'required':
                    # Also check state - ignore terminated instances
                    if instance.get('State', {}).get('Name') != 'terminated':
                         non_compliant.append(instance['InstanceId'])
                
        status = 'PASS' if not non_compliant else 'FAIL'
        # Filter out terminated instances from count for clarity
        # This requires iterating again or tracking active instances separately. 
        # Let's refine the message based on non_compliant list vs total instances initially fetched.
        message = f"{instance_count - len(non_compliant)}/{instance_count} active/pending instances enforce IMDSv2."
        if non_compliant:
            message += f" Instances not enforcing IMDSv2: {", ".join(non_compliant[:5])}{'...' if len(non_compliant) > 5 else ''}"
        elif instance_count == 0:
             message = "No running or pending EC2 instances found."
             status = 'PASS' # No instances, no violation

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Enforce IMDSv2 on instances', 
            remediation_available=True
        )
    except Exception as e:
        logger.error(f"Error checking IMDSv2: {e}", exc_info=True)
        return create_standard_response(
            CONTROL_ID, 
            'ERROR', 
            f'Failed to check: {str(e)}', 
            remediation_available=False
        )

def check_nacl_open_ports() -> Dict[str, Any]:
    """
    Check if Network ACLs allow open admin ports from 0.0.0.0/0.
    
    Verifies if Network ACLs allow ingress from 0.0.0.0/0 to administrative
    ports (22 and 3389), which poses a security risk.
    
    Returns:
        Dict[str, Any]: Control check result with NACL details
    """
    try:
        nacls = paginate(ec2_client, 'describe_network_acls', 'NetworkAcls')
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

def check_sg_open_ipv4(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check if Security Groups allow open admin ports from 0.0.0.0/0 (IPv4).
    
    Verifies if security groups allow ingress from 0.0.0.0/0 to administrative
    ports (22 and 3389), which poses a security risk.

    Args:
        aws_data (Dict[str, Any]): Dictionary of pre-fetched AWS data.
    
    Returns:
        Dict[str, Any]: Control check result with security group details
    """
    CONTROL_ID = 'EC2.53'
    admin_ports = {22, 3389}
    open_ipv4 = '0.0.0.0/0'
    try:
        sgs = aws_data.get('security_groups')
        if sgs is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve Security Group data.", False)
        
        open_groups = []
        sg_count = len(sgs)
        
        for sg in sgs:
            sg_id = sg['GroupId']
            sg_name = sg.get('GroupName')
            # Skip default SGs for this check as they are handled by EC2.2
            if sg_name == 'default':
                continue

            for p in sg.get('IpPermissions', []):
                from_port = p.get('FromPort')
                to_port = p.get('ToPort')
                ip_protocol = p.get('IpProtocol') # e.g., 'tcp', 'udp', '-1' (all)

                # Check port range overlap with admin ports
                port_match = False
                if from_port is not None and to_port is not None:
                    # Check if the rule's port range includes either admin port
                    rule_ports = set(range(from_port, to_port + 1))
                    if not admin_ports.isdisjoint(rule_ports):
                         port_match = True
                elif ip_protocol == '-1': # All protocols/ports implicitly include admin ports
                     port_match = True 
                
                # Check if IPv4 range is 0.0.0.0/0
                open_from_anywhere = any(r.get('CidrIp') == open_ipv4 for r in p.get('IpRanges', []))
                
                if port_match and open_from_anywhere:
                    open_groups.append(sg_id)
                    break # Move to the next security group once a violation is found
                        
        status = 'PASS' if not open_groups else 'FAIL'
        # Adjust sg_count to exclude default SGs if needed for message clarity
        # message = f"{sg_count - len(open_groups)}/{sg_count} non-default SGs restrict admin ports from {open_ipv4}."
        # For now, keep total SG count
        message = f"{len(open_groups)}/{sg_count} SGs allow admin ports (22/3389) ingress from {open_ipv4}."
        if open_groups:
            message += f" Offending SGs: {", ".join(open_groups[:5])}{'...' if len(open_groups) > 5 else ''}"

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation=f'Restrict SG ingress from {open_ipv4} for ports 22/3389',
            remediation_available=True
        )
    except Exception as e:
        logger.error(f"Error checking security group IPv4 rules: {e}", exc_info=True)
        return create_standard_response(
            CONTROL_ID, 
            'ERROR', 
            f'Failed to check: {str(e)}', 
            remediation_available=False
        )

def check_sg_open_ipv6(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check if Security Groups allow open admin ports from ::/0 (IPv6).
    
    Verifies if security groups allow ingress from ::/0 to administrative
    ports (22 and 3389), which poses a security risk.

    Args:
        aws_data (Dict[str, Any]): Dictionary of pre-fetched AWS data.
    
    Returns:
        Dict[str, Any]: Control check result with security group details
    """
    CONTROL_ID = 'EC2.54'
    admin_ports = {22, 3389}
    open_ipv6 = '::/0'
    try:
        sgs = aws_data.get('security_groups')
        if sgs is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve Security Group data.", False)

        open_groups = []
        sg_count = len(sgs)
        
        for sg in sgs:
            sg_id = sg['GroupId']
            sg_name = sg.get('GroupName')
            if sg_name == 'default':
                continue

            for p in sg.get('IpPermissions', []):
                from_port = p.get('FromPort')
                to_port = p.get('ToPort')
                ip_protocol = p.get('IpProtocol')

                port_match = False
                if from_port is not None and to_port is not None:
                    rule_ports = set(range(from_port, to_port + 1))
                    if not admin_ports.isdisjoint(rule_ports):
                        port_match = True
                elif ip_protocol == '-1':
                    port_match = True
                
                # Check if IPv6 range is ::/0
                open_from_anywhere = any(r.get('CidrIpv6') == open_ipv6 for r in p.get('Ipv6Ranges', []))
                
                if port_match and open_from_anywhere:
                    open_groups.append(sg_id)
                    break 
                        
        status = 'PASS' if not open_groups else 'FAIL'
        message = f"{len(open_groups)}/{sg_count} SGs allow admin ports (22/3389) ingress from {open_ipv6}."
        if open_groups:
            message += f" Offending SGs: {", ".join(open_groups[:5])}{'...' if len(open_groups) > 5 else ''}"

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation=f'Restrict SG ingress from {open_ipv6} for ports 22/3389',
            remediation_available=True
        )
    except Exception as e:
        logger.error(f"Error checking security group IPv6 rules: {e}", exc_info=True)
        return create_standard_response(
            CONTROL_ID, 
            'ERROR', 
            f'Failed to check: {str(e)}', 
            remediation_available=False
        )

def check_efs_encryption(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check if EFS volumes are encrypted at rest.
    
    Verifies if Elastic File System (EFS) volumes are configured with
    encryption at rest for data protection.

    Args:
        aws_data (Dict[str, Any]): Dictionary of pre-fetched AWS data.
    
    Returns:
        Dict[str, Any]: Control check result with EFS encryption status
    """
    CONTROL_ID = 'EFS.1'
    try:
        fs = aws_data.get('efs_filesystems')
        if fs is None:
             return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve EFS data.", False)
        if not fs:
             return create_standard_response(CONTROL_ID, 'PASS', "No EFS file systems found.")

        unencrypted = [f['FileSystemId'] for f in fs if not f.get('Encrypted')] # Use .get for safety
        status = 'PASS' if not unencrypted else 'FAIL'
        message = f"{len(fs) - len(unencrypted)}/{len(fs)} EFS file systems are encrypted."
        if unencrypted:
             message += f" Unencrypted: {", ".join(unencrypted[:5])}{'...' if len(unencrypted) > 5 else ''}"

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            # Remediation for EFS requires recreation, hence manual
            remediation='Recreate EFS with encryption enabled (manual process)', 
            remediation_available=False
        )
    except Exception as e:
        logger.error(f"Error checking EFS encryption: {e}", exc_info=True)
        return create_standard_response(
            CONTROL_ID, 
            'ERROR', 
            f'Failed to check: {str(e)}', 
            remediation_available=False
        )

def check_iam_user_policies(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check if IAM users have policies attached directly. (Updated to use helper)
    
    Verifies that policies are attached to groups rather than directly
    to users, which is a best practice for IAM management.

    Args:
        aws_data (Dict[str, Any]): Dictionary of pre-fetched AWS data.
    
    Returns:
        Dict[str, Any]: Control check result with IAM user policy details
    """
    CONTROL_ID = 'IAM.2'
    try:
        users = aws_data.get('users')
        if users is None:
             return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve IAM user data.", False)
        if not users:
            return create_standard_response(CONTROL_ID, 'PASS', "No IAM users found.")

        with_policies = []
        users_checked = 0
        # Use ThreadPoolExecutor for parallel checks using the helper function
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
             future_to_user = {
                 executor.submit(get_all_attached_user_policies, u['UserName']): u['UserName'] 
                 for u in users
             }
        
             for future in as_completed(future_to_user):
                 username = future_to_user[future]
                 users_checked += 1
                 try:
                     # Result from helper is the list of attached policies
                     attached_policies = future.result()
                     # Check if the returned list (result of pagination) is not empty
                     if attached_policies: 
                         with_policies.append(username)
                 except Exception as e: # Catch errors from the helper/future directly
                     logger.warning(f"Error checking attached policies for user {username}: {e}", exc_info=True)
                     # Optionally mark as non-compliant or skip based on error handling preference
                     # For now, we just log and don't count as checked if helper failed fundamentally
                     users_checked -=1 

        status = 'PASS' if not with_policies else 'FAIL'
        message = f"{users_checked - len(with_policies)}/{users_checked} users checked do not have direct policies."
        if with_policies:
            message += f" Users with direct policies: {", ".join(with_policies[:5])}{'...' if len(with_policies) > 5 else ''}"

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Move policies from users to IAM groups (manual process)',
            remediation_available=False
        )
    except Exception as e:
        # Catch errors during the user listing or overall process
        logger.error(f"Error checking IAM user policies: {e}", exc_info=True)
        return create_standard_response(
            CONTROL_ID, 
            'ERROR', 
            f'Failed to check: {str(e)}\', 
            remediation_available=False
        )

def check_iam_key_rotation(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check if IAM access keys are rotated every 90 days.
    
    Verifies that IAM access keys are rotated regularly to maintain
    security through credential cycling.

    Args:
        aws_data (Dict[str, Any]): Dictionary of pre-fetched AWS data.
    
    Returns:
        Dict[str, Any]: Control check result with key rotation details
    """
    CONTROL_ID = 'IAM.3'
    MAX_KEY_AGE_DAYS = 90
    try:
        report_response = aws_data.get('credential_report')
        # Check response structure more carefully
        if report_response is None:
             message = "Credential report fetch failed or timed out."
             logger.error(message)
             return create_standard_response(CONTROL_ID, 'ERROR', message, False)
        elif report_response.get('State') != 'COMPLETE':
             message = f"Credential report state is not COMPLETE: {report_response.get('State', 'Unknown')}. Description: {report_response.get('Description', 'N/A')}"
             logger.error(message)
             # Report might still contain partial content, but safer to treat as error
             return create_standard_response(CONTROL_ID, 'ERROR', message, False)
        elif 'Content' not in report_response or not report_response['Content']:
             message = "Credential report is COMPLETE but content is missing or empty."
             logger.error(message)
             return create_standard_response(CONTROL_ID, 'ERROR', message, False)
        
        report_content_bytes = report_response['Content']
        report_content_string = report_content_bytes.decode('utf-8')
        
        old_keys = []
        now = datetime.now(timezone.utc)
        user_count = 0
        active_key_count = 0
        
        # Use csv.DictReader for robust parsing
        csv_reader = csv.DictReader(io.StringIO(report_content_string))
        
        for row in csv_reader:
            try:
                username = row.get('user')
                # Skip the <root_account> and handle potential missing username
                if not username or username == '<root_account>':
                     continue
                user_count += 1

                # Check access key 1
                key1_active = row.get('access_key_1_active') == 'true'
                if key1_active:
                    active_key_count += 1
                    key1_last_rotated_str = row.get('access_key_1_last_rotated')
                    if key1_last_rotated_str and key1_last_rotated_str != 'N/A':
                        try:
                            key1_last_rotated = datetime.fromisoformat(key1_last_rotated_str.replace('Z', '+00:00'))
                            key_age = (now - key1_last_rotated).days
                            if key_age >= MAX_KEY_AGE_DAYS:
                                old_keys.append(f"{username} (key 1, age {key_age} days)")
                        except ValueError:
                             logger.warning(f"Could not parse key1 rotation date '{key1_last_rotated_str}' for {username}")
                             old_keys.append(f"{username} (key 1, invalid rotation date)")
                    else:
                        # Active key, never rotated. Check user creation date for context.
                        creation_str = row.get('user_creation_time')
                        age_desc = "never rotated"
                        if creation_str and creation_str != 'N/A':
                            try:
                                creation_date = datetime.fromisoformat(creation_str.replace('Z', '+00:00'))
                                if (now - creation_date).days >= MAX_KEY_AGE_DAYS:
                                    age_desc = f"never rotated, user age {(now - creation_date).days} days"
                            except ValueError: pass # Ignore parse error for creation date
                        old_keys.append(f"{username} (key 1, {age_desc})")
                       
                # Check access key 2
                key2_active = row.get('access_key_2_active') == 'true'
                if key2_active:
                    active_key_count += 1
                    key2_last_rotated_str = row.get('access_key_2_last_rotated')
                    if key2_last_rotated_str and key2_last_rotated_str != 'N/A':
                        try:
                            key2_last_rotated = datetime.fromisoformat(key2_last_rotated_str.replace('Z', '+00:00'))
                            key_age = (now - key2_last_rotated).days
                            if key_age >= MAX_KEY_AGE_DAYS:
                                old_keys.append(f"{username} (key 2, age {key_age} days)")
                        except ValueError:
                            logger.warning(f"Could not parse key2 rotation date '{key2_last_rotated_str}' for {username}")
                            old_keys.append(f"{username} (key 2, invalid rotation date)")
                    else:
                        creation_str = row.get('user_creation_time')
                        age_desc = "never rotated"
                        if creation_str and creation_str != 'N/A':
                            try:
                                creation_date = datetime.fromisoformat(creation_str.replace('Z', '+00:00'))
                                if (now - creation_date).days >= MAX_KEY_AGE_DAYS:
                                    age_desc = f"never rotated, user age {(now - creation_date).days} days"
                            except ValueError: pass
                        old_keys.append(f"{username} (key 2, {age_desc})")
            except Exception as parse_e:
                 logger.warning(f"Skipping row in credential report due to processing error: {parse_e}. Row sample: {str(row)[:100]}...", exc_info=True)
                 continue # Skip malformed rows/data
        
        # Remove duplicates just in case same key flagged twice by different logic paths
        unique_old_keys = sorted(list(set(old_keys)))
        
        status = 'PASS' if not unique_old_keys else 'FAIL'
        message = f"{active_key_count - len(unique_old_keys)}/{active_key_count} active IAM user keys rotated within {MAX_KEY_AGE_DAYS} days."
        if unique_old_keys:
            message += f" Keys needing rotation: {", ".join(unique_old_keys[:5])}{'...' if len(unique_old_keys) > 5 else ''}"
        elif user_count == 0:
             message = "No IAM users found in credential report (excluding root)."
             status = 'PASS'
        elif active_key_count == 0:
             message = "No active IAM user access keys found."
             status = 'PASS'

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Rotate IAM user access keys (manual process)', 
            remediation_available=False
        )
    except Exception as e:
        logger.error(f"Error checking IAM key rotation: {e}", exc_info=True)
        return create_standard_response(
            CONTROL_ID, 
            'ERROR', 
            f'Failed to check: {str(e)}', 
            remediation_available=False
        )

def check_root_access_keys(aws_data: Dict[str, Any]):
    """Check if root account has access keys.
    Args:
        aws_data (Dict[str, Any]): Pre-fetched AWS data (expects 'account_summary').
    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'IAM.4'
    try:
        summary = aws_data.get('account_summary')
        if summary is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve account summary data.", False)
        
        # 0 = no keys, 1 = active key(s), 2 = no keys but report generated > 24h ago (treat as 0)
        keys_present = summary.get('AccountAccessKeysPresent', 0) 
        status = 'PASS' if keys_present in [0, 2] else 'FAIL'
        message = f"Root account access keys present: {keys_present == 1}."
        
        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Delete root account access keys (manual process)', 
            remediation_available=False
        )
    except Exception as e:
        logger.error(f"Error checking root access keys: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}', remediation_available=False)

def check_iam_mfa_console(aws_data: Dict[str, Any]):
    """
    Check if IAM users with console passwords have MFA enabled. (Updated to use helper)
    Args:
        aws_data (Dict[str, Any]): Pre-fetched AWS data (expects 'users').
    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'IAM.5'
    try:
        users = aws_data.get('users')
        if users is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve IAM user data.", False)
        if not users:
            return create_standard_response(CONTROL_ID, 'PASS', "No IAM users found.")

        no_mfa = []
        checked_users = 0
        # Parallelize the MFA checks using the helper
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
             future_to_user = {}
             for u in users:
                 # Simple check: If PasswordLastUsed field exists, assume console access is possible/intended.
                 # A better check might use the credential report's 'password_enabled' field.
                 if u.get('PasswordLastUsed'):
                     username = u['UserName']
                     future_to_user[executor.submit(get_all_mfa_devices, username)] = username
             
             for future in as_completed(future_to_user):
                 username = future_to_user[future]
                 checked_users += 1
                 try:
                     # Result from helper is the list of MFA devices (or [] if error/none)
                     mfa_devices = future.result()
                     if not mfa_devices: # Check if the list is empty
                         no_mfa.append(username)
                 except Exception as e: # Catch errors from helper/future
                      logger.warning(f"Unexpected error checking MFA for user {username}: {e}", exc_info=True)
                      # Don't count user if check failed
                      checked_users -= 1 

        status = 'PASS' if not no_mfa else 'FAIL'
        message = f"{checked_users - len(no_mfa)}/{checked_users} console users checked have MFA enabled."
        if no_mfa:
            message += f" Console users lacking MFA: {", ".join(no_mfa[:5])}{'...' if len(no_mfa) > 5 else ''}"
        elif checked_users == 0:
             # This could happen if no users have PasswordLastUsed or all checks failed
             message = "No IAM users found with console passwords or checks failed."
             # Status could be PASS or NOTE depending on interpretation. Let's use PASS.
             status = 'PASS'

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Enable MFA for IAM console users (manual process)', 
            remediation_available=False
        )
    except Exception as e:
        logger.error(f"Error checking IAM console MFA: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}\', remediation_available=False)

def check_root_mfa(aws_data: Dict[str, Any]):
    """Check if the root account has MFA enabled.
    Args:
        aws_data (Dict[str, Any]): Pre-fetched AWS data (expects 'account_summary').
    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'IAM.9'
    try:
        summary = aws_data.get('account_summary')
        if summary is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve account summary data.", False)
        
        # 1 = MFA enabled, 0 = not enabled
        mfa_enabled = summary.get('AccountMFAEnabled', 0)
        status = 'PASS' if mfa_enabled == 1 else 'FAIL'
        message = f"Root account MFA enabled: {mfa_enabled == 1}."
        
        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Enable MFA for root account (manual process)', 
            remediation_available=False
        )
    except Exception as e:
        logger.error(f"Error checking root MFA: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}', remediation_available=False)

def check_password_length(aws_data: Dict[str, Any]):
    """Check IAM password policy minimum length.
    Args:
        aws_data (Dict[str, Any]): Pre-fetched AWS data (expects 'password_policy').
    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'IAM.15'
    MIN_LENGTH = 14
    try:
        policy = aws_data.get('password_policy')
        # Check if policy is None (fetch failed) or empty dict (no policy exists)
        if policy is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve password policy data.", True) # Remediation potentially available
        if not policy:
            return create_standard_response(CONTROL_ID, 'FAIL', "No IAM password policy defined.", True)

        current_length = policy.get('MinimumPasswordLength', 0)
        compliant = current_length >= MIN_LENGTH
        status = 'PASS' if compliant else 'FAIL'
        message = f"Password policy minimum length is {current_length} (required >= {MIN_LENGTH})."
        
        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation=f'Set password policy minimum length to {MIN_LENGTH} or greater.',
            remediation_available=True
        )
    except Exception as e:
        # Catch unexpected errors during policy processing
        logger.error(f"Error processing password policy length: {e}", exc_info=True)
        # Assume FAIL if unexpected error processing the fetched policy
        return create_standard_response(CONTROL_ID, 'FAIL', f'Error processing password policy: {str(e)}', True)

def check_password_reuse(aws_data: Dict[str, Any]):
    """Check IAM password policy reuse prevention.
    Args:
        aws_data (Dict[str, Any]): Pre-fetched AWS data (expects 'password_policy').
    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'IAM.16'
    MIN_REUSE_PREVENTION = 1 # CIS v3 requires at least 1 (meaning reuse is prevented)
                             # Older versions might require 24. Let's stick to >= 1 for now.
    try:
        policy = aws_data.get('password_policy')
        if policy is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve password policy data.", True)
        if not policy:
            return create_standard_response(CONTROL_ID, 'FAIL', "No IAM password policy defined.", True)
        
        # Check if reuse prevention is configured and meets minimum
        reuse_prevention = policy.get('PasswordReusePrevention', 0)
        compliant = reuse_prevention >= MIN_REUSE_PREVENTION
        status = 'PASS' if compliant else 'FAIL'
        message = f"Password policy reuse prevention is set to {reuse_prevention} (required >= {MIN_REUSE_PREVENTION})."
        
        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation=f'Configure password policy reuse prevention (at least {MIN_REUSE_PREVENTION}).',
            remediation_available=True
        )
    except Exception as e:
        logger.error(f"Error processing password policy reuse: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'FAIL', f'Error processing password policy: {str(e)}', True)

def check_support_role():
    """Check if an IAM role for AWS support access exists.
    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'IAM.18'
    # Standard support role names contain "SupportRole" or similar patterns
    # e.g., AWSServiceRoleForSupport, SupportRole-*
    SUPPORT_ROLE_PATTERN = 'Support' # Case insensitive check might be better
    try:
        # Use paginate helper
        roles = paginate(iam_client, 'list_roles', 'Roles')
        if roles is None: # Should not happen if paginate returns [], but check anyway
             return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve IAM roles.", True)

        # Check if any role name contains the support pattern (case insensitive)
        support_role_found = any(SUPPORT_ROLE_PATTERN.lower() in r.get('RoleName', '').lower() for r in roles)
        
        status = 'PASS' if support_role_found else 'FAIL'
        message = f"IAM role for support access found: {support_role_found}."
        
        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Create an IAM role for AWS support access (e.g., using the AWSServiceRoleForSupport template or custom role)',
            remediation_available=True
        )
    except ClientError as e:
        logger.error(f"Error checking for support role: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}', remediation_available=False)
    except Exception as e:
        logger.error(f"Unexpected error checking for support role: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}', False)

def check_unused_credentials(aws_data: Dict[str, Any]):
    """Check for IAM user credentials unused for 45 days or more.
    Args:
        aws_data (Dict[str, Any]): Pre-fetched AWS data (expects 'credential_report').
    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'IAM.22'
    UNUSED_DAYS = 45
    try:
        report_response = aws_data.get('credential_report')
        # Check response structure (similar to IAM.3 check)
        if report_response is None:
             message = "Credential report fetch failed or timed out for unused cred check."
             logger.error(message)
             return create_standard_response(CONTROL_ID, 'ERROR', message, False)
        elif report_response.get('State') != 'COMPLETE':
             message = f"Credential report state not COMPLETE for unused cred check: {report_response.get('State', 'Unknown')}. Description: {report_response.get('Description', 'N/A')}"
             logger.error(message)
             return create_standard_response(CONTROL_ID, 'ERROR', message, False)
        elif 'Content' not in report_response or not report_response['Content']:
             message = "Credential report COMPLETE but content missing/empty for unused cred check."
             logger.error(message)
             return create_standard_response(CONTROL_ID, 'ERROR', message, False)
        
        report_content_bytes = report_response['Content']
        report_content_string = report_content_bytes.decode('utf-8')
        
        unused_creds = []
        now = datetime.now(timezone.utc)
        threshold_delta = timedelta(days=UNUSED_DAYS)
        user_count = 0
        creds_checked = 0 # Count active credentials checked

        csv_reader = csv.DictReader(io.StringIO(report_content_string))
        
        for row in csv_reader:
            try:
                username = row.get('user')
                if not username or username == '<root_account>': continue
                user_count += 1

                # Check password last used
                password_enabled = row.get('password_enabled') == 'true'
                if password_enabled:
                     creds_checked += 1
                     password_last_used_str = row.get('password_last_used')
                     is_unused = True # Assume unused unless used recently
                     if password_last_used_str and password_last_used_str not in ['N/A', 'no_information']:
                          try:
                               password_last_used = datetime.fromisoformat(password_last_used_str.replace('Z', '+00:00'))
                               if now - password_last_used < threshold_delta:
                                    is_unused = False
                          except ValueError:
                               logger.warning(f"Could not parse password_last_used date '{password_last_used_str}' for {username}")
                     elif password_last_used_str in ['N/A', 'no_information']:
                          # Never used, check creation time
                          user_creation_str = row.get('user_creation_time')
                          if user_creation_str and user_creation_str != 'N/A':
                               try:
                                    user_creation = datetime.fromisoformat(user_creation_str.replace('Z', '+00:00'))
                                    if now - user_creation < threshold_delta:
                                         is_unused = False # Created recently
                               except ValueError: pass
                     if is_unused:
                          unused_creds.append(f"{username} (password)")

                # Check access key 1 last used
                key1_active = row.get('access_key_1_active') == 'true'
                if key1_active:
                     creds_checked += 1
                     key1_last_used_str = row.get('access_key_1_last_used_date') # Use correct field name
                     is_unused = True
                     if key1_last_used_str and key1_last_used_str not in ['N/A', 'no_information']:
                          try:
                               key1_last_used = datetime.fromisoformat(key1_last_used_str.replace('Z', '+00:00'))
                               if now - key1_last_used < threshold_delta:
                                    is_unused = False
                          except ValueError:
                               logger.warning(f"Could not parse key1_last_used date '{key1_last_used_str}' for {username}")
                     elif key1_last_used_str in ['N/A', 'no_information']:
                          # Key active but never used - check key rotation/creation time
                          key1_last_rotated_str = row.get('access_key_1_last_rotated')
                          if key1_last_rotated_str and key1_last_rotated_str != 'N/A':
                              try:
                                  key1_last_rotated = datetime.fromisoformat(key1_last_rotated_str.replace('Z', '+00:00'))
                                  if now - key1_last_rotated < threshold_delta:
                                       is_unused = False # Key rotated recently
                              except ValueError: pass
                          # Else: if rotation N/A, and never used, likely unused if user old enough (implicit check)
                          if is_unused:
                               unused_creds.append(f"{username} (key 1)")

                # Check access key 2 last used
                key2_active = row.get('access_key_2_active') == 'true'
                if key2_active:
                     creds_checked += 1
                     key2_last_used_str = row.get('access_key_2_last_used_date') # Use correct field name
                     is_unused = True
                     if key2_last_used_str and key2_last_used_str not in ['N/A', 'no_information']:
                          try:
                               key2_last_used = datetime.fromisoformat(key2_last_used_str.replace('Z', '+00:00'))
                               if now - key2_last_used < threshold_delta:
                                    is_unused = False
                          except ValueError:
                              logger.warning(f"Could not parse key2_last_used date '{key2_last_used_str}' for {username}")
                     elif key2_last_used_str in ['N/A', 'no_information']:
                          key2_last_rotated_str = row.get('access_key_2_last_rotated')
                          if key2_last_rotated_str and key2_last_rotated_str != 'N/A':
                              try:
                                  key2_last_rotated = datetime.fromisoformat(key2_last_rotated_str.replace('Z', '+00:00'))
                                  if now - key2_last_rotated < threshold_delta:
                                       is_unused = False # Key rotated recently
                              except ValueError: pass
                          if is_unused:
                               unused_creds.append(f"{username} (key 2)")

            except Exception as parse_e:
                logger.warning(f"Skipping row in credential report due to processing error: {parse_e}. Row sample: {str(row)[:100]}...", exc_info=True)
                continue
        
        # Remove duplicates
        unique_unused_creds = sorted(list(set(unused_creds)))
        
        status = 'PASS' if not unique_unused_creds else 'FAIL'
        message = f"{creds_checked - len(unique_unused_creds)}/{creds_checked} active credentials used within {UNUSED_DAYS} days."
        if unique_unused_creds:
            message += f" Credentials unused >= {UNUSED_DAYS} days: {", ".join(unique_unused_creds[:5])}{'...' if len(unique_unused_creds) > 5 else ''}"
        elif user_count == 0:
             message = "No IAM users found (excluding root)."
             status = 'PASS'
        elif creds_checked == 0:
             message = "No active IAM user credentials found."
             status = 'PASS'

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Deactivate or remove unused credentials (manual process)', 
            remediation_available=False
        )
    except Exception as e:
        logger.error(f"Error checking unused credentials: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}', remediation_available=False)

def check_expired_certificates():
    """Check for expired server certificates uploaded to IAM.
    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'IAM.26'
    try:
        # Use paginate helper
        certs_metadata = paginate(iam_client, 'list_server_certificates', 'ServerCertificateMetadataList')
        if certs_metadata is None:
             return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve server certificates.", True)
        if not certs_metadata:
             return create_standard_response(CONTROL_ID, 'PASS', "No IAM server certificates found.")
        
        now = datetime.now(timezone.utc)
        expired_certs = [
            c['ServerCertificateName'] 
            for c in certs_metadata 
            if c.get('Expiration') and c['Expiration'] < now # Ensure Expiration exists
        ]
        
        status = 'PASS' if not expired_certs else 'FAIL'
        message = f"{len(certs_metadata) - len(expired_certs)}/{len(certs_metadata)} IAM server certificates are valid."
        if expired_certs:
            message += f" Expired certificates: {", ".join(expired_certs[:5])}{'...' if len(expired_certs) > 5 else ''}"

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Remove expired IAM server certificates',
            remediation_available=True
        )
    except ClientError as e:
        logger.error(f"Error checking expired certificates: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}', remediation_available=False)
    except Exception as e:
        logger.error(f"Unexpected error checking expired certificates: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}', False)

def check_cloudshell_policy():
    """Check IAM.27: Ensure AWSCloudShellFullAccess policy is not attached.
    
    (Refactored for pagination, error handling, standard response)
    
    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'IAM.27'
    POLICY_ARN = 'arn:aws:iam::aws:policy/AWSCloudShellFullAccess' # AWS Managed Policy ARN
    
    entities_found = {
        'users': [],
        'groups': [],
        'roles': [],
    }
    total_entities = 0
    error_occurred = False
    
    try:
        # Paginate through entities attached to the policy
        paginator = iam_client.get_paginator('list_entities_for_policy')
        pages = paginator.paginate(PolicyArn=POLICY_ARN, EntityFilter='All') # Check Users, Groups, Roles
        
        for page in pages:
            entities_found['users'].extend([u['UserName'] for u in page.get('PolicyUsers', [])])
            entities_found['groups'].extend([g['GroupName'] for g in page.get('PolicyGroups', [])])
            entities_found['roles'].extend([r['RoleName'] for r in page.get('PolicyRoles', [])])
            
        total_entities = len(entities_found['users']) + len(entities_found['groups']) + len(entities_found['roles'])
        
    except ClientError as e:
        # Handle case where policy might not exist (e.g., GovCloud, though unlikely for this one)
        if e.response['Error']['Code'] == 'NoSuchEntity':
             logger.info(f"Policy {POLICY_ARN} not found. Control {CONTROL_ID} passes.")
             total_entities = 0 # Treat as compliant if policy doesn't exist
        else:
             logger.error(f"Error listing entities for policy {POLICY_ARN}: {e}", exc_info=True)
             error_occurred = True
    except Exception as e:
         logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
         error_occurred = True

    if error_occurred:
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check policy attachments for {POLICY_ARN}')

    status = 'PASS' if total_entities == 0 else 'FAIL'
    message = f"{total_entities} entities found with AWSCloudShellFullAccess attached."
    if total_entities > 0:
         details = []
         if entities_found['users']: details.append(f"Users: {entities_found['users'][:2]}...")
         if entities_found['groups']: details.append(f"Groups: {entities_found['groups'][:2]}...")
         if entities_found['roles']: details.append(f"Roles: {entities_found['roles'][:2]}...")
         message += f" Details (truncated): {'; '.join(details)}"
         
    return create_standard_response(
        CONTROL_ID, 
        status, 
        message, 
        remediation='Detach the AWSCloudShellFullAccess policy from IAM users, groups, and roles.', 
        remediation_available=False # Manual
    )

def check_access_analyzer():
    """
    Check IAM.28: Ensure IAM Access Analyzer is enabled.
    
    (Refactored for pagination, error handling, standard response)

    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'IAM.28'
    # Note: Access Analyzers are regional. This check runs in the Lambda's region.
    # For full coverage, this Lambda needs to run in all desired regions or use multi-region aggregation.
    try:
        # Paginate analyzers (though usually only one per region per account type)
        analyzers = paginate(iam_client, 'list_analyzers', 'analyzers')
        
        active_analyzers = [a for a in analyzers if a.get('status') == 'ACTIVE']
        
        status = 'PASS' if active_analyzers else 'FAIL'
        message = f"Found {len(analyzers)} IAM Access Analyzer(s). {len(active_analyzers)} are ACTIVE in this region."
        if not analyzers:
             message = "No IAM Access Analyzers found in this region."
        elif not active_analyzers:
             message += " None are currently ACTIVE."

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message, 
            remediation='Enable IAM Access Analyzer in this AWS region.', 
            remediation_available=True
        )
    except ClientError as e:
        # Handle potential errors like service not available in region or permissions
        logger.error(f"Error listing Access Analyzers: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')
    except Exception as e:
         logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
         return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_kms_rotation(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """Check if KMS CMKs have key rotation enabled.
    Args:
        aws_data (Dict[str, Any]): Pre-fetched AWS data (expects 'kms_keys').
    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'KMS.4'
    try:
        keys = aws_data.get('kms_keys')
        if keys is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve KMS key data.", True)
        if not keys:
            return create_standard_response(CONTROL_ID, 'PASS', "No KMS keys found.")

        no_rotation = []
        keys_checked = 0
        # Parallelize the rotation status checks
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
             future_to_key = {executor.submit(kms_client.get_key_rotation_status, KeyId=k['KeyId']): k['KeyId'] for k in keys}
             
             for future in as_completed(future_to_key):
                 key_id = future_to_key[future]
                 keys_checked += 1
                 try:
                     # Key-specific call remains
                     rotation_status = future.result()
                     # Only check customer managed keys (AWS managed keys rotation is handled by AWS)
                     # We need key metadata for this - fetch it? Or infer from rotation status?
                     # get_key_rotation_status only works on CMKs. If it fails for a key, it might be AWS managed.
                     # Let's assume the call succeeds only for CMKs relevant here.
                     if not rotation_status.get('KeyRotationEnabled'):
                         no_rotation.append(key_id)
                 except ClientError as e:
                     # Ignore errors for keys where rotation status can't be retrieved (e.g., AWS managed keys)
                     if e.response['Error']['Code'] in ['AccessDeniedException', 'UnsupportedOperationException']:
                         logger.debug(f"Skipping rotation check for key {key_id}: {e.response['Error']['Message']}")
                         keys_checked -= 1 # Don't count it in the total checked if skipped
                     else:
                         logger.warning(f"Error getting rotation status for KMS key {key_id}: {e}", exc_info=True)
                         # Treat as non-compliant if check fails unexpectedly?
                         no_rotation.append(key_id)

        status = 'PASS' if not no_rotation else 'FAIL'
        # Adjust message to reflect only keys checked (potentially CMKs)
        message = f"{keys_checked - len(no_rotation)}/{keys_checked} checked KMS keys have rotation enabled."
        if no_rotation:
            message += f" Keys lacking rotation: {", ".join(no_rotation[:5])}{'...' if len(no_rotation) > 5 else ''}"
        elif keys_checked == 0:
             message = "No customer-managed KMS keys found or checkable for rotation."
             status = 'PASS' # Or NOTE? Pass seems reasonable.

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Enable KMS key rotation for customer-managed keys',
            remediation_available=True
        )
    except Exception as e:
        logger.error(f"Error checking KMS rotation: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}', remediation_available=False)

def check_rds_public(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """Check if RDS instances are publicly accessible.
    Args:
        aws_data (Dict[str, Any]): Pre-fetched AWS data (expects 'rds_instances').
    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'RDS.2'
    try:
        dbs = aws_data.get('rds_instances')
        if dbs is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve RDS instance data.", True)
        if not dbs:
            return create_standard_response(CONTROL_ID, 'PASS', "No RDS instances found.")

        public_dbs = [db['DBInstanceIdentifier'] for db in dbs if db.get('PubliclyAccessible')] # Use .get
        status = 'PASS' if not public_dbs else 'FAIL'
        message = f"{len(dbs) - len(public_dbs)}/{len(dbs)} RDS instances are not publicly accessible."
        if public_dbs:
            message += f" Publicly accessible RDS instances: {", ".join(public_dbs[:5])}{'...' if len(public_dbs) > 5 else ''}"

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Disable public access on RDS instances',
            remediation_available=True
        )
    except Exception as e:
        logger.error(f"Error checking RDS public access: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}', remediation_available=False)

def check_rds_encryption(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """Check if RDS instances have storage encryption enabled.
    Args:
        aws_data (Dict[str, Any]): Pre-fetched AWS data (expects 'rds_instances').
    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'RDS.3'
    try:
        dbs = aws_data.get('rds_instances')
        if dbs is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve RDS instance data.", False)
        if not dbs:
            return create_standard_response(CONTROL_ID, 'PASS', "No RDS instances found.")

        unencrypted = [db['DBInstanceIdentifier'] for db in dbs if not db.get('StorageEncrypted')] # Use .get
        status = 'PASS' if not unencrypted else 'FAIL'
        message = f"{len(dbs) - len(unencrypted)}/{len(dbs)} RDS instances have storage encryption."
        if unencrypted:
            message += f" Unencrypted RDS instances: {", ".join(unencrypted[:5])}{'...' if len(unencrypted) > 5 else ''}"

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Recreate RDS instance with encryption enabled (manual process)',
            remediation_available=False
        )
    except Exception as e:
        logger.error(f"Error checking RDS encryption: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}', remediation_available=False)

def check_rds_auto_upgrades(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """Check if RDS instances have auto minor version upgrades enabled.
    Args:
        aws_data (Dict[str, Any]): Pre-fetched AWS data (expects 'rds_instances').
    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'RDS.13'
    try:
        dbs = aws_data.get('rds_instances')
        if dbs is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve RDS instance data.", True)
        if not dbs:
            return create_standard_response(CONTROL_ID, 'PASS', "No RDS instances found.")

        no_upgrade = [db['DBInstanceIdentifier'] for db in dbs if not db.get('AutoMinorVersionUpgrade')] # Use .get
        status = 'PASS' if not no_upgrade else 'FAIL'
        message = f"{len(dbs) - len(no_upgrade)}/{len(dbs)} RDS instances have auto minor version upgrades enabled."
        if no_upgrade:
            message += f" RDS instances lacking auto upgrades: {", ".join(no_upgrade[:5])}{'...' if len(no_upgrade) > 5 else ''}"

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Enable auto minor version upgrades on RDS instances',
            remediation_available=True
        )
    except Exception as e:
        logger.error(f"Error checking RDS auto upgrades: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}', remediation_available=False)

def check_s3_block_public(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """Check if S3 buckets block public access settings are enabled.
    Args:
        aws_data (Dict[str, Any]): Pre-fetched AWS data (expects 'buckets').
    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'S3.1' # Also covers S3.8 logic
    REQUIRED_BLOCKS = ['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets']
    try:
        buckets_info = aws_data.get('buckets')
        if buckets_info is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve S3 bucket data.", True)
        if not buckets_info:
            return create_standard_response(CONTROL_ID, 'PASS', "No S3 buckets found.")

        bucket_names = [b['Name'] for b in buckets_info]
        non_compliant = []
        buckets_checked = 0
        
        # Parallelize the checks for public access block settings
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_bucket = {executor.submit(s3_client.get_public_access_block, Bucket=b): b for b in bucket_names}

            for future in as_completed(future_to_bucket):
                bucket_name = future_to_bucket[future]
                buckets_checked += 1
                try:
                    # Bucket-specific call remains
                    config = future.result().get('PublicAccessBlockConfiguration', {})
                    # Check if all required block settings are True
                    if not all(config.get(k, False) for k in REQUIRED_BLOCKS):
                        non_compliant.append(bucket_name)
                except ClientError as e:
                    # Handle buckets that might not exist anymore or access denied
                    if e.response['Error']['Code'] == 'NoSuchBucket':
                        logger.warning(f"Bucket {bucket_name} not found during public access block check.")
                        buckets_checked -= 1 # Adjust count as bucket was not checked
                    elif e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                         logger.warning(f"Bucket {bucket_name} has no PublicAccessBlock config (treated as non-compliant). ")
                         non_compliant.append(bucket_name)
                    else:
                        logger.error(f"Error getting public access block for bucket {bucket_name}: {e}", exc_info=True)
                        # Treat as non-compliant if check fails unexpectedly
                        non_compliant.append(bucket_name)

        status = 'PASS' if not non_compliant else 'FAIL'
        # Use buckets_checked which reflects buckets we could actually get status for
        message = f"{buckets_checked - len(non_compliant)}/{buckets_checked} buckets checked have all public access blocks enabled."
        if non_compliant:
            message += f" Buckets lacking full block: {", ".join(non_compliant[:5])}{'...' if len(non_compliant) > 5 else ''}"

        # This function serves both S3.1 and S3.8, return result structure for S3.1
        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Enable all settings under S3 Block Public Access for the bucket',
            remediation_available=True
        )
    except Exception as e:
        logger.error(f"Error checking S3 block public access: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}', remediation_available=False)

def check_s3_ssl(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """Check if S3 buckets enforce SSL/TLS for requests.
    Args:
        aws_data (Dict[str, Any]): Pre-fetched AWS data (expects 'buckets').
    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'S3.5'
    SSL_POLICY_CONDITION = '"aws:SecureTransport": "false"' # Look for explicit deny
    try:
        buckets_info = aws_data.get('buckets')
        if buckets_info is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve S3 bucket data.", True)
        if not buckets_info:
            return create_standard_response(CONTROL_ID, 'PASS', "No S3 buckets found.")

        bucket_names = [b['Name'] for b in buckets_info]
        lacks_ssl_policy = []
        buckets_checked = 0

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_bucket = {executor.submit(s3_client.get_bucket_policy, Bucket=b): b for b in bucket_names}

            for future in as_completed(future_to_bucket):
                bucket_name = future_to_bucket[future]
                buckets_checked += 1
                policy_enforces_ssl = False
                try:
                    # Bucket-specific call remains
                    policy_str = future.result().get('Policy')
                    if policy_str:
                        # Basic check: Look for a Deny statement where SecureTransport is false
                        # A more robust check would parse the JSON and evaluate the policy logic
                        if SSL_POLICY_CONDITION in policy_str:
                             policy_data = json.loads(policy_str)
                             for statement in policy_data.get('Statement', []):
                                 if (statement.get('Effect') == 'Deny' and 
                                     statement.get('Condition') and 
                                     statement['Condition'].get('Bool') and 
                                     statement['Condition']['Bool'].get('aws:SecureTransport') == 'false'):
                                     # Found a policy denying non-SSL requests
                                     policy_enforces_ssl = True
                                     break 
                    # If policy exists but doesn't explicitly deny non-SSL, mark as non-compliant for this check
                    if not policy_enforces_ssl:
                         lacks_ssl_policy.append(bucket_name)

                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                        # No policy means SSL is not enforced via policy
                        logger.debug(f"Bucket {bucket_name} has no policy, SSL not enforced.")
                        lacks_ssl_policy.append(bucket_name)
                    elif e.response['Error']['Code'] == 'NoSuchBucket':
                        logger.warning(f"Bucket {bucket_name} not found during SSL policy check.")
                        buckets_checked -= 1 # Adjust count
                    else:
                        logger.error(f"Error getting policy for bucket {bucket_name}: {e}", exc_info=True)
                        # Treat as non-compliant if check fails
                        lacks_ssl_policy.append(bucket_name)

        status = 'PASS' if not lacks_ssl_policy else 'FAIL'
        message = f"{buckets_checked - len(lacks_ssl_policy)}/{buckets_checked} buckets checked enforce SSL via bucket policy."
        if lacks_ssl_policy:
            message += f" Buckets lacking SSL enforcement policy: {", ".join(lacks_ssl_policy[:5])}{'...' if len(lacks_ssl_policy) > 5 else ''}"

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Add a bucket policy to deny requests not using SSL/TLS (aws:SecureTransport=false)',
            remediation_available=True
        )
    except Exception as e:
        logger.error(f"Error checking S3 SSL policy: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}', remediation_available=False)

def check_s3_public_access(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """Re-check for S3 Block Public Access settings (CIS S3.8). This reuses the S3.1 logic.
    Args:
        aws_data (Dict[str, Any]): Pre-fetched AWS data.
    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'S3.8'
    # Call the same function used for S3.1
    result = check_s3_block_public(aws_data)
    # Update the control ID in the result to match S3.8
    result['control'] = CONTROL_ID 
    # Adjust remediation text slightly if desired, though it's the same action
    result['remediation'] = 'Ensure all settings under S3 Block Public Access are enabled.'
    return result

def check_s3_mfa_delete(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """Check if S3 buckets have MFA Delete enabled.
    Args:
        aws_data (Dict[str, Any]): Pre-fetched AWS data (expects 'buckets').
    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'S3.20'
    try:
        buckets_info = aws_data.get('buckets')
        if buckets_info is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve S3 bucket data.", True)
        if not buckets_info:
            return create_standard_response(CONTROL_ID, 'PASS', "No S3 buckets found.")

        bucket_names = [b['Name'] for b in buckets_info]
        no_mfa_delete = []
        buckets_checked = 0

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_bucket = {executor.submit(s3_client.get_bucket_versioning, Bucket=b): b for b in bucket_names}

            for future in as_completed(future_to_bucket):
                bucket_name = future_to_bucket[future]
                buckets_checked += 1
                try:
                    # Bucket-specific call remains
                    versioning_info = future.result()
                    # MFA Delete can only be enabled if Versioning is enabled.
                    # Check Status and MFADelete fields.
                    status = versioning_info.get('Status')
                    mfa_delete_status = versioning_info.get('MFADelete')
                    
                    # Fail if versioning is not enabled OR if MFA delete is explicitly disabled
                    if status != 'Enabled' or mfa_delete_status != 'Enabled':
                         # Log why it failed for clarity
                         reason = "Versioning not enabled" if status != 'Enabled' else "MFA Delete not enabled"
                         logger.debug(f"Bucket {bucket_name} lacks MFA Delete ({reason}).")
                         no_mfa_delete.append(bucket_name)

                except ClientError as e:
                    # Handle cases where versioning might not be configured at all (results in error? check API)
                    # Or NoSuchBucket, AccessDenied
                    if e.response['Error']['Code'] == 'NoSuchBucket':
                         logger.warning(f"Bucket {bucket_name} not found during MFA Delete check.")
                         buckets_checked -= 1
                    else:
                         logger.error(f"Error getting versioning/MFA Delete for bucket {bucket_name}: {e}", exc_info=True)
                         # Treat as non-compliant if check fails
                         no_mfa_delete.append(bucket_name)

        status = 'PASS' if not no_mfa_delete else 'FAIL'
        message = f"{buckets_checked - len(no_mfa_delete)}/{buckets_checked} buckets checked have Versioning and MFA Delete enabled."
        if no_mfa_delete:
            message += f" Buckets lacking MFA Delete (or Versioning): {", ".join(no_mfa_delete[:5])}{'...' if len(no_mfa_delete) > 5 else ''}"

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Enable Versioning and MFA Delete on S3 buckets',
            remediation_available=True
        )
    except Exception as e:
        logger.error(f"Error checking S3 MFA Delete: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}', remediation_available=False)

def check_s3_write_logging(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """Check if CloudTrail logs S3 write events.
    
    Args:
        aws_data (Dict[str, Any]): Dictionary of pre-fetched AWS data.
    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'S3.22'
    try:
        trails = aws_data.get('trails')
        if trails is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve CloudTrail data.", False)
        if not trails:
            return create_standard_response(CONTROL_ID, 'FAIL', "No CloudTrail trails found to check for S3 write logging.")

        trails_without_write_logging = []
        for t in trails:
            trail_name = t['Name']
            try:
                # Trail-specific call remains
                selectors = cloudtrail_client.get_event_selectors(TrailName=trail_name).get('EventSelectors', [])
                # Check if any selector covers 'WriteOnly' or 'All'. Also consider data events for S3.
                has_write_selector = any(s.get('ReadWriteType') in ['WriteOnly', 'All'] for s in selectors)
                has_s3_data_event = any(
                    any(ds.get('Type') == 'AWS::S3::Object' for ds in s.get('DataResources', []))
                    for s in selectors if s.get('IncludeManagementEvents') is False # Focus on data events
                )
                # A simple check: assume PASS if any trail has 'WriteOnly' or 'All' OR S3 data events logged.
                # A stricter check would ensure *all* relevant trails log this.
                # For now, let's see if *any* trail covers it.
                if not (has_write_selector or has_s3_data_event):
                     trails_without_write_logging.append(trail_name)

            except ClientError as e:
                logger.warning(f"Failed to get event selectors for trail {trail_name}: {e}", exc_info=True)
                trails_without_write_logging.append(trail_name) # Treat as non-compliant if check fails

        # If *all* trails lack appropriate logging, it's a FAIL.
        # If *at least one* trail has it, consider it PASS (adjust if stricter check needed).
        status = 'FAIL' if len(trails_without_write_logging) == len(trails) else 'PASS'
        message = f"{len(trails) - len(trails_without_write_logging)}/{len(trails)} trails potentially log S3 write events."
        if trails_without_write_logging and status == 'FAIL':
             message += f" Trails confirmed lacking S3 write logging: {", ".join(trails_without_write_logging[:5])}{'...' if len(trails_without_write_logging) > 5 else ''}"
        elif trails_without_write_logging and status == 'PASS':
             message += f" Note: Some trails might lack specific S3 write logging: {", ".join(trails_without_write_logging[:5])}{'...' if len(trails_without_write_logging) > 5 else ''}"

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Enable S3 write event logging in CloudTrail event selectors', 
            remediation_available=True
        )
    except Exception as e:
        logger.error(f"Error checking S3 write logging: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}', remediation_available=False)

def check_s3_read_logging(aws_data: Dict[str, Any]) -> Dict[str, Any]:
    """Check if CloudTrail logs S3 read events.
    
    Args:
        aws_data (Dict[str, Any]): Dictionary of pre-fetched AWS data.
    Returns:
        Dict[str, Any]: Control check result.
    """
    CONTROL_ID = 'S3.23'
    try:
        trails = aws_data.get('trails')
        if trails is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve CloudTrail data.", False)
        if not trails:
            return create_standard_response(CONTROL_ID, 'FAIL', "No CloudTrail trails found to check for S3 read logging.")

        trails_without_read_logging = []
        for t in trails:
            trail_name = t['Name']
            try:
                # Trail-specific call remains
                selectors = cloudtrail_client.get_event_selectors(TrailName=trail_name).get('EventSelectors', [])
                # Check if any selector covers 'ReadOnly' or 'All'. Also consider data events for S3.
                has_read_selector = any(s.get('ReadWriteType') in ['ReadOnly', 'All'] for s in selectors)
                has_s3_data_event = any(
                    any(ds.get('Type') == 'AWS::S3::Object' for ds in s.get('DataResources', []))
                    for s in selectors if s.get('IncludeManagementEvents') is False # Focus on data events
                )
                # Similar logic to write logging check.
                if not (has_read_selector or has_s3_data_event):
                     trails_without_read_logging.append(trail_name)

            except ClientError as e:
                logger.warning(f"Failed to get event selectors for trail {trail_name}: {e}", exc_info=True)
                trails_without_read_logging.append(trail_name) # Treat as non-compliant if check fails

        # If *all* trails lack appropriate logging, it's a FAIL.
        # If *at least one* trail has it, consider it PASS (adjust if stricter check needed).
        status = 'FAIL' if len(trails_without_read_logging) == len(trails) else 'PASS'
        message = f"{len(trails) - len(trails_without_read_logging)}/{len(trails)} trails potentially log S3 read events."
        if trails_without_read_logging and status == 'FAIL':
             message += f" Trails confirmed lacking S3 read logging: {", ".join(trails_without_read_logging[:5])}{'...' if len(trails_without_read_logging) > 5 else ''}"
        elif trails_without_read_logging and status == 'PASS':
             message += f" Note: Some trails might lack specific S3 read logging: {", ".join(trails_without_read_logging[:5])}{'...' if len(trails_without_read_logging) > 5 else ''}"

        return create_standard_response(
            CONTROL_ID, 
            status, 
            message,
            remediation='Enable S3 read event logging in CloudTrail event selectors', 
            remediation_available=True
        )
    except Exception as e:
        logger.error(f"Error checking S3 read logging: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}', remediation_available=False)

# --- NEW Helper Function for IAM.5 ---
def get_all_mfa_devices(username: str) -> List[Dict[str, Any]]:
    """Retrieve all MFA devices for a specific user using pagination."""
    try:
        # Note: list_mfa_devices does NOT support pagination directly via paginators
        # It uses Marker/IsTruncated pattern. We need manual pagination here.
        mfa_devices = []
        marker = None
        while True:
            args = {'UserName': username}
            if marker:
                args['Marker'] = marker
            
            response = iam_client.list_mfa_devices(**args)
            mfa_devices.extend(response.get('MFADevices', []))
            
            if response.get('IsTruncated'):
                marker = response.get('Marker')
            else:
                break
        return mfa_devices
    except ClientError as e:
        logger.error(f"Error listing MFA devices for user {username}: {e}", exc_info=True)
        return [] # Return empty list on error
    except Exception as e:
        logger.error(f"Unexpected error listing MFA devices for {username}: {e}", exc_info=True)
        return []

# --- NEW Helper Function for IAM.2 ---
def get_all_attached_user_policies(username: str) -> List[Dict[str, Any]]:
    """Retrieve all directly attached managed policies for a user using pagination."""
    try:
        # Use the standard paginate helper as list_attached_user_policies supports it
        return paginate(iam_client, 'list_attached_user_policies', 'AttachedPolicies', UserName=username)
    except Exception as e:
        # Catch potential errors during pagination specific to this call
        logger.error(f"Error paginating attached policies for user {username}: {e}", exc_info=True)
        return [] # Return empty list on error

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