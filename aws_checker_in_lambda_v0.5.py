import json
import boto3
import os
import logging
import time # Added for duration calculation
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone, timedelta # Added timedelta
from botocore.config import Config
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed

# Version: 0.6 - Added more core checks

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configuration from environment variables
REPORT_BUCKET = os.environ.get('REPORT_BUCKET', 'cis-compliance-reports-v0-5') # Example bucket
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
logger.setLevel(LOG_LEVEL)

# Configure retry settings for AWS clients
retry_config = Config(
    retries={'max_attempts': 3, 'mode': 'standard'}
)

# AWS clients
iam_client = boto3.client('iam', config=retry_config)
s3_client = boto3.client('s3', config=retry_config)
ec2_client = boto3.client('ec2', config=retry_config)
cloudtrail_client = boto3.client('cloudtrail', config=retry_config)
config_client = boto3.client('config', config=retry_config) # Added Config client
kms_client = boto3.client('kms', config=retry_config) # Added KMS client

MAX_WORKERS = 10 # Increased slightly for more parallel checks

# --- Helper Functions ---

def paginate(client, method_name: str, result_key: str, **kwargs) -> List[Dict[str, Any]]:
    """Generic pagination helper for boto3 list/describe calls."""
    paginator = client.get_paginator(method_name)
    results = []
    try:
        for page in paginator.paginate(**kwargs):
            results.extend(page.get(result_key, []))
        return results
    except ClientError as e:
        # Log specific common errors potentially indicating service not enabled or permissions issues
        if e.response['Error']['Code'] in ['AccessDeniedException', 'UnrecognizedClientException', 'InvalidClientTokenId']:
             logger.warning(f"Access denied or client error during pagination for {method_name} (Check permissions/region): {e}")
        else:
             logger.error(f"Pagination failed for {method_name} with args {kwargs}: {e}", exc_info=True)
        return []
    except Exception as e:
        logger.error(f"Unexpected error during pagination for {method_name}: {e}", exc_info=True)
        return []

def create_standard_response(control_id: str, status: str, message: str, remediation: Optional[str] = None, remediation_available: bool = False) -> Dict[str, Any]:
    """Creates a standard dictionary structure for check results."""
    return {
        'control': control_id,
        'status': status,
        'message': message,
        'remediation': remediation if remediation is not None else "See control documentation.",
        'remediation_available': remediation_available
    }

# --- Control Evaluation Functions (v0.6 Subset) ---

def check_security_contact() -> Dict[str, Any]:
    """Check Account.1: Ensure security contact information is registered (checks account alias)."""
    CONTROL_ID = 'Account.1'
    try:
        response = iam_client.list_account_aliases()
        alias_exists = bool(response.get('AccountAliases'))
        status = 'PASS' if alias_exists else 'FAIL'
        message = 'Account alias exists.' if alias_exists else 'Account alias does not exist.'
        return create_standard_response(
            CONTROL_ID, status, message,
            remediation='Create an AWS account alias in the IAM console.',
            remediation_available=False
        )
    except ClientError as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_cloudtrail_multi_region() -> Dict[str, Any]:
    """Check CloudTrail.1: Ensure at least one multi-region CloudTrail exists."""
    CONTROL_ID = 'CloudTrail.1'
    try:
        trails = paginate(cloudtrail_client, 'describe_trails', 'trailList')
        if not trails:
             return create_standard_response(CONTROL_ID, 'FAIL', 'No CloudTrail trails found.',
                                            remediation='Enable CloudTrail in the AWS console.', remediation_available=True)

        multi_region_trail_found = any(t.get('IsMultiRegionTrail') for t in trails)
        status = 'PASS' if multi_region_trail_found else 'FAIL'
        message = f"Found {len(trails)} trail(s). Multi-region trail found: {multi_region_trail_found}."
        return create_standard_response(
            CONTROL_ID, status, message,
            remediation='Ensure at least one CloudTrail trail is configured as multi-region.',
            remediation_available=True
        )
    except ClientError as e:
        # Catch case where CloudTrail might not be enabled/accessible
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_cloudtrail_encryption() -> Dict[str, Any]:
    """Check CloudTrail.2: Ensure CloudTrail trails are encrypted with KMS CMKs."""
    CONTROL_ID = 'CloudTrail.2'
    try:
        trails = paginate(cloudtrail_client, 'describe_trails', 'trailList')
        if not trails:
             return create_standard_response(CONTROL_ID, 'PASS', 'No CloudTrail trails found.')

        non_encrypted = [t['Name'] for t in trails if not t.get('KmsKeyId')]
        status = 'PASS' if not non_encrypted else 'FAIL'
        message = f"{len(trails) - len(non_encrypted)}/{len(trails)} trails are encrypted with KMS."
        if non_encrypted:
             message += f" Non-encrypted trails: {", ".join(non_encrypted[:3])}{'...' if len(non_encrypted) > 3 else ''}"

        return create_standard_response(
            CONTROL_ID, status, message,
            remediation='Enable KMS encryption for listed CloudTrail trails.',
            remediation_available=True
        )
    except ClientError as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

# --- NEW: Config.1 ---
def check_config_enabled() -> Dict[str, Any]:
    """Check Config.1: Ensure AWS Config is enabled."""
    CONTROL_ID = 'Config.1'
    try:
        recorders = paginate(config_client, 'describe_configuration_recorders', 'ConfigurationRecorders')
        
        is_enabled = False
        if recorders:
             # Check status of the first recorder found. A simple check for v0.5/0.6.
             try:
                  status_resp = config_client.describe_configuration_recorder_status(
                       ConfigurationRecorderNames=[recorders[0]['name']]
                  )
                  if status_resp.get('ConfigurationRecordersStatus') and \
                     status_resp['ConfigurationRecordersStatus'][0].get('recording'):
                       is_enabled = True
             except ClientError as status_e:
                  # If status check fails but recorder exists, assume potentially enabled but not verifiable
                  logger.warning(f"Could not get status for config recorder {recorders[0].get('name')}: {status_e}")
                  is_enabled = True # Treat as enabled if recorder exists but status fails

        status_msg = 'Config enabled and recorder is recording.' if is_enabled else \
                     'Config recorder found but may not be recording or status unknown.' if recorders else \
                     'Config is not enabled (no recorders found).'
        final_status = 'PASS' if is_enabled else 'FAIL'

        return create_standard_response(
            CONTROL_ID, final_status, status_msg,
            remediation='Enable AWS Config and start the configuration recorder in this region.',
            remediation_available=True
        )
    except ClientError as e:
         # Handle case where Config service might not be enabled at all in the region
         logger.warning(f"Error checking AWS Config (potential service/permission issue): {e}", exc_info=True)
         return create_standard_response(
             CONTROL_ID, 'FAIL', f'Config not enabled or error checking: {str(e)}',
             remediation='Enable AWS Config', remediation_available=True
         )
    except Exception as e:
         logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
         return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

# --- NEW: EC2.6 ---
def check_vpc_flow_logs() -> Dict[str, Any]:
    """Check EC2.6: Ensure VPC flow logs are enabled."""
    CONTROL_ID = 'EC2.6'
    try:
        flow_logs = paginate(ec2_client, 'describe_flow_logs', 'FlowLogs')
        
        active_logs_count = sum(1 for log in flow_logs if log.get('FlowLogStatus') == 'ACTIVE')
        
        status = 'PASS' if active_logs_count > 0 else 'FAIL'
        message = f"Found {len(flow_logs)} VPC flow log(s), {active_logs_count} are ACTIVE."
        if not flow_logs:
             message = "No VPC flow logs found."
        elif active_logs_count == 0:
             message += " No flow logs are currently ACTIVE."

        return create_standard_response(
            CONTROL_ID, status, message,
            remediation='Enable VPC flow logs for VPCs and ensure they are in the ACTIVE state.',
            remediation_available=True
        )
    except ClientError as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_ebs_encryption() -> Dict[str, Any]:
    """Check EC2.7: Ensure EBS default encryption is enabled."""
    CONTROL_ID = 'EC2.7'
    try:
        response = ec2_client.get_ebs_encryption_by_default()
        is_enabled = response.get('EbsEncryptionByDefault', False)
        status = 'PASS' if is_enabled else 'FAIL'
        message = f"EBS default encryption is {'enabled' if is_enabled else 'disabled'} in this region."
        return create_standard_response(
            CONTROL_ID, status, message,
            remediation='Enable EBS default encryption in EC2 settings for this region.',
            remediation_available=True
        )
    except ClientError as e:
        # Handle case where API might not be available (e.g., older regions) or permissions
        if e.response['Error']['Code'] == 'UnsupportedOperation':
             logger.warning(f"{CONTROL_ID}: EBS default encryption setting not supported in this region.")
             # Treat as PASS or N/A? Let's be conservative and FAIL.
             return create_standard_response(CONTROL_ID, 'FAIL', 'EBS default encryption setting not supported/checkable in this region.')
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

# --- NEW: IAM.2 ---
def check_iam_user_policies() -> Dict[str, Any]:
    """Check IAM.2: Ensure IAM policies are attached to groups or roles, not users."""
    CONTROL_ID = 'IAM.2'
    try:
        users = paginate(iam_client, 'list_users', 'Users')
        if not users:
            return create_standard_response(CONTROL_ID, 'PASS', "No IAM users found.")

        users_with_direct_policies = []
        futures = {}
        users_checked = 0

        # Use ThreadPoolExecutor for parallel checks on each user's policies
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for user in users:
                username = user['UserName']
                # Submit the pagination call for listing policies attached to *this* user
                futures[executor.submit(paginate, iam_client, 'list_attached_user_policies', 'AttachedPolicies', UserName=username)] = username

            for future in as_completed(futures):
                username = futures[future]
                users_checked += 1
                try:
                    # Result of the future is the list of attached policies for that user
                    attached_policies = future.result()
                    if attached_policies: # If the list is not empty
                        users_with_direct_policies.append(username)
                except Exception as policy_e:
                    # Log error for the specific user but continue checking others
                    logger.warning(f"Could not check attached policies for user {username}: {policy_e}", exc_info=True)
                    # Optionally treat error as FAIL for that user by adding to list? For now, just log.

        status = 'PASS' if not users_with_direct_policies else 'FAIL'
        message = f"{users_checked - len(users_with_direct_policies)}/{users_checked} users checked do not have directly attached policies."
        if users_with_direct_policies:
            message += f" Users with direct policies: {", ".join(users_with_direct_policies[:3])}{'...' if len(users_with_direct_policies) > 3 else ''}"

        return create_standard_response(
            CONTROL_ID, status, message,
            remediation='Attach IAM policies to groups or roles instead of users.',
            remediation_available=False # Manual process generally
        )
    except ClientError as e:
        logger.error(f"Error listing users for {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to list users: {str(e)}')
    except Exception as e:
         logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
         return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

# --- NEW: IAM.3 ---
def _get_credential_report() -> Optional[List[Dict]]:
    """Helper to get and parse the IAM credential report."""
    try:
        # Ensure report is generated
        iam_client.generate_credential_report()
        report_state = ''
        attempts = 0
        while report_state != 'COMPLETE' and attempts < 10:
            report_info = iam_client.get_credential_report()
            report_state = report_info.get('State')
            if report_state == 'COMPLETE':
                content_bytes = report_info.get('Content')
                if not content_bytes:
                     logger.error("Credential report content is empty.")
                     return None
                # Decode and parse CSV
                content = content_bytes.decode('utf-8')
                lines = content.splitlines()
                if not lines: return []
                header = lines[0].split(',')
                report_data = [dict(zip(header, line.split(','))) for line in lines[1:]]
                return report_data
            elif report_state == 'FAILED':
                logger.error(f"Credential report generation failed: {report_info.get('Description')}")
                return None
            attempts += 1
            logger.info(f"Waiting for credential report generation... attempt {attempts}")
            time.sleep(2) # Wait before checking again

        logger.error("Credential report did not become available in time.")
        return None
    except ClientError as e:
        logger.error(f"Failed to get/generate credential report: {e}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"Unexpected error getting credential report: {e}", exc_info=True)
        return None

def check_iam_key_rotation() -> Dict[str, Any]:
    """Check IAM.3: Ensure IAM user access keys are rotated within 90 days."""
    CONTROL_ID = 'IAM.3'
    MAX_KEY_AGE_DAYS = 90
    try:
        report = _get_credential_report()
        if report is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Could not retrieve IAM credential report.")

        old_keys = []
        now = datetime.now(timezone.utc)
        user_count = 0
        active_key_count = 0

        for user in report:
            username = user.get('user')
            if not username or username == '<root_account>':
                continue
            user_count += 1

            for key_num in ['1', '2']:
                key_active = user.get(f'access_key_{key_num}_active') == 'true'
                if key_active:
                    active_key_count += 1
                    last_rotated_str = user.get(f'access_key_{key_num}_last_rotated')
                    if last_rotated_str and last_rotated_str != 'N/A':
                        try:
                            # Handle potential variations in timestamp format if needed
                            last_rotated = datetime.fromisoformat(last_rotated_str.replace('Z', '+00:00'))
                            key_age = (now - last_rotated).days
                            if key_age >= MAX_KEY_AGE_DAYS:
                                old_keys.append(f"{username} (key {key_num}, age {key_age} days)")
                        except ValueError:
                            logger.warning(f"Could not parse date '{last_rotated_str}' for {username} key {key_num}")
                            old_keys.append(f"{username} (key {key_num}, invalid rotation date)")
                    else:
                        # Active key but never rotated (last_rotated is N/A or missing)
                        # Check user creation time as a fallback for age? Simpler: just flag it.
                         creation_str = user.get('user_creation_time')
                         age_desc = "never rotated"
                         if creation_str and creation_str != 'N/A':
                              try:
                                   creation_date = datetime.fromisoformat(creation_str.replace('Z', '+00:00'))
                                   if (now - creation_date).days >= MAX_KEY_AGE_DAYS:
                                        age_desc = f"never rotated, user created {(now - creation_date).days} days ago"
                              except ValueError: pass # Ignore creation date parse error
                         old_keys.append(f"{username} (key {key_num}, {age_desc})")


        status = 'PASS' if not old_keys else 'FAIL'
        message = f"{active_key_count - len(old_keys)}/{active_key_count} active IAM user keys rotated within {MAX_KEY_AGE_DAYS} days."
        if old_keys:
            message += f" Keys needing rotation: {", ".join(old_keys[:3])}{'...' if len(old_keys) > 3 else ''}"
        elif user_count == 0:
             message = "No IAM users found in credential report (excluding root)."
             status = 'PASS'
        elif active_key_count == 0:
             message = "No active IAM user access keys found."
             status = 'PASS'

        return create_standard_response(
            CONTROL_ID, status, message,
            remediation=f'Rotate IAM user access keys older than {MAX_KEY_AGE_DAYS} days.',
            remediation_available=False # Manual process
        )
    except Exception as e:
        logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_root_access_keys() -> Dict[str, Any]:
    """Check IAM.4: Ensure root account access keys do not exist."""
    CONTROL_ID = 'IAM.4'
    try:
        summary = iam_client.get_account_summary()
        keys_present = summary.get('SummaryMap', {}).get('AccountAccessKeysPresent', 0)
        status = 'PASS' if keys_present in [0, 2] else 'FAIL'
        message = f"Root account access keys found: {keys_present == 1}."
        return create_standard_response(
            CONTROL_ID, status, message,
            remediation='Delete root account access keys via the IAM console (Security Credentials page).',
            remediation_available=False
        )
    except ClientError as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_root_mfa() -> Dict[str, Any]:
    """Check IAM.9: Ensure MFA is enabled for the root account."""
    CONTROL_ID = 'IAM.9'
    try:
        summary = iam_client.get_account_summary()
        mfa_enabled = summary.get('SummaryMap', {}).get('AccountMFAEnabled', 0)
        status = 'PASS' if mfa_enabled == 1 else 'FAIL'
        message = f"Root account MFA enabled: {mfa_enabled == 1}."
        return create_standard_response(
            CONTROL_ID, status, message,
            remediation='Enable MFA for the root account via the IAM console (Security Credentials page).',
            remediation_available=False
        )
    except ClientError as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

# --- NEW: IAM.22 ---
def check_unused_credentials() -> Dict[str, Any]:
    """Check IAM.22: Ensure IAM credentials unused for 45 days or more are deactivated."""
    CONTROL_ID = 'IAM.22'
    UNUSED_DAYS_THRESHOLD = 45
    try:
        report = _get_credential_report()
        if report is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Could not retrieve IAM credential report.")

        unused_creds = []
        now = datetime.now(timezone.utc)
        threshold_delta = timedelta(days=UNUSED_DAYS_THRESHOLD)
        user_count = 0
        active_creds_count = 0

        for user in report:
            username = user.get('user')
            if not username or username == '<root_account>':
                continue
            user_count += 1

            # Check Password
            password_enabled = user.get('password_enabled') == 'true'
            if password_enabled:
                 active_creds_count += 1
                 last_used_str = user.get('password_last_used')
                 is_unused = True # Assume unused unless proven otherwise
                 if last_used_str and last_used_str not in ['N/A', 'no_information']:
                      try:
                           last_used = datetime.fromisoformat(last_used_str.replace('Z', '+00:00'))
                           if now - last_used < threshold_delta:
                                is_unused = False
                      except ValueError:
                           logger.warning(f"Could not parse password_last_used date '{last_used_str}' for {username}")
                 elif last_used_str in ['N/A', 'no_information']:
                      # Never used, check creation time
                      creation_str = user.get('user_creation_time')
                      if creation_str and creation_str != 'N/A':
                           try:
                                creation_date = datetime.fromisoformat(creation_str.replace('Z', '+00:00'))
                                if now - creation_date < threshold_delta:
                                     is_unused = False # User created recently
                           except ValueError: pass # Ignore parse error
                 if is_unused:
                      unused_creds.append(f"{username} (password)")

            # Check Access Keys
            for key_num in ['1', '2']:
                key_active = user.get(f'access_key_{key_num}_active') == 'true'
                if key_active:
                    active_creds_count += 1
                    last_used_str = user.get(f'access_key_{key_num}_last_used_date')
                    is_unused = True
                    if last_used_str and last_used_str not in ['N/A', 'no_information']:
                        try:
                            last_used = datetime.fromisoformat(last_used_str.replace('Z', '+00:00'))
                            if now - last_used < threshold_delta:
                                is_unused = False
                        except ValueError:
                             logger.warning(f"Could not parse key_{key_num}_last_used date '{last_used_str}' for {username}")
                    elif last_used_str in ['N/A', 'no_information']:
                         # Key active but never used, check rotation/creation time
                         rotated_str = user.get(f'access_key_{key_num}_last_rotated')
                         if rotated_str and rotated_str != 'N/A':
                              try:
                                   rotated_date = datetime.fromisoformat(rotated_str.replace('Z', '+00:00'))
                                   if now - rotated_date < threshold_delta:
                                        is_unused = False # Key created/rotated recently
                              except ValueError: pass
                         # If rotation date also N/A, could check user creation as fallback, but it gets complex.
                         # Simplification: if key active, never used, and rotation date > threshold (or N/A), mark unused.

                    if is_unused:
                         unused_creds.append(f"{username} (key {key_num})")

        # Remove duplicates (e.g., user password and key1 unused)
        unique_unused_creds = sorted(list(set(unused_creds)))

        status = 'PASS' if not unique_unused_creds else 'FAIL'
        message = f"{active_creds_count - len(unique_unused_creds)}/{active_creds_count} active IAM credentials used within {UNUSED_DAYS_THRESHOLD} days."
        if unique_unused_creds:
            message += f" Unused credentials (>= {UNUSED_DAYS_THRESHOLD} days): {", ".join(unique_unused_creds[:3])}{'...' if len(unique_unused_creds) > 3 else ''}"
        elif user_count == 0:
             message = "No IAM users found in credential report (excluding root)."
             status = 'PASS'
        elif active_creds_count == 0:
             message = "No active IAM user credentials found."
             status = 'PASS'

        return create_standard_response(
            CONTROL_ID, status, message,
            remediation=f'Deactivate or remove IAM credentials unused for {UNUSED_DAYS_THRESHOLD} days or more.',
            remediation_available=False # Manual process
        )
    except Exception as e:
        logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

# --- NEW: KMS.4 ---
def check_kms_rotation() -> Dict[str, Any]:
    """Check KMS.4: Ensure KMS Customer Managed Keys (CMKs) have rotation enabled."""
    CONTROL_ID = 'KMS.4'
    try:
        # List only CMKs (filter handled by API/permissions ideally, or post-filter)
        # list_keys doesn't filter by origin, need to check rotation status which fails for AWS managed keys.
        keys = paginate(kms_client, 'list_keys', 'Keys')
        if not keys:
            return create_standard_response(CONTROL_ID, 'PASS', "No KMS keys found.")

        keys_without_rotation = []
        cmk_checked_count = 0
        futures = {}

        # Check rotation status in parallel
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for key in keys:
                key_id = key['KeyId']
                futures[executor.submit(kms_client.get_key_rotation_status, KeyId=key_id)] = key_id

            for future in as_completed(futures):
                key_id = futures[future]
                try:
                    rotation_status = future.result()
                    # If call succeeds, it's likely a CMK we can check
                    cmk_checked_count += 1
                    if not rotation_status.get('KeyRotationEnabled'):
                        keys_without_rotation.append(key_id)
                except ClientError as e:
                    # Errors expected for non-CMKs or keys pending deletion etc.
                    if e.response['Error']['Code'] in ['AccessDeniedException', 'UnsupportedOperationException', 'NotFoundException', 'KMSInvalidStateException']:
                         logger.debug(f"Skipping rotation check for key {key_id}: {e.response['Error']['Code']}")
                    else:
                         # Log unexpected errors for a key, potentially treat as non-compliant?
                         logger.warning(f"Error getting rotation status for KMS key {key_id}: {e}", exc_info=True)
                         keys_without_rotation.append(f"{key_id} (Error)") # Mark error keys

        status = 'PASS' if not keys_without_rotation else 'FAIL'
        message = f"{cmk_checked_count - len(keys_without_rotation)}/{cmk_checked_count} checkable KMS keys have rotation enabled."
        if keys_without_rotation:
            message += f" Keys needing rotation (or error checking): {", ".join(keys_without_rotation[:3])}{'...' if len(keys_without_rotation) > 3 else ''}"
        elif cmk_checked_count == 0:
             message = "No checkable Customer Managed KMS keys found."
             status = 'PASS' # If no CMKs exist, this control passes

        return create_standard_response(
            CONTROL_ID, status, message,
            remediation='Enable annual key rotation for Customer Managed KMS keys.',
            remediation_available=True
        )
    except ClientError as e:
        logger.error(f"Error listing keys for {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to list keys: {str(e)}')
    except Exception as e:
        logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_s3_block_public() -> Dict[str, Any]:
    """Check S3.1 / S3.8: Ensure all S3 buckets block public access."""
    CONTROL_ID = 'S3.1'
    REQUIRED_BLOCKS = ['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets']
    try:
        buckets = paginate(s3_client, 'list_buckets', 'Buckets')
        if not buckets:
            return create_standard_response(CONTROL_ID, 'PASS', 'No S3 buckets found.')

        non_compliant = []
        futures = {}
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for bucket in buckets:
                bucket_name = bucket['Name']
                futures[executor.submit(s3_client.get_public_access_block, Bucket=bucket_name)] = bucket_name

            for future in as_completed(futures):
                bucket_name = futures[future]
                try:
                    config = future.result().get('PublicAccessBlockConfiguration', {})
                    if not all(config.get(k, False) for k in REQUIRED_BLOCKS):
                        non_compliant.append(bucket_name)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                         logger.warning(f"Bucket {bucket_name} has no PublicAccessBlock config.")
                         non_compliant.append(bucket_name)
                    elif e.response['Error']['Code'] == 'NoSuchBucket':
                         logger.warning(f"Bucket {bucket_name} not found during check.")
                    elif e.response['Error']['Code'] == 'AccessDenied':
                         logger.warning(f"Access denied checking PublicAccessBlock for {bucket_name}")
                         non_compliant.append(f"{bucket_name} (Access Denied)") # Treat as non-compliant if cannot check
                    else:
                         logger.error(f"Error getting public access block for {bucket_name}: {e}", exc_info=True)
                         non_compliant.append(f"{bucket_name} (Error)")

        status = 'PASS' if not non_compliant else 'FAIL'
        # Count buckets we could actually check (excluding vanished ones)
        checked_bucket_count = len(futures) - sum(1 for b in non_compliant if 'not found' in str(b).lower()) # Approximate count
        message = f"{checked_bucket_count - len(non_compliant)}/{checked_bucket_count} buckets checked have all public access blocks enabled."
        if non_compliant:
            message += f" Buckets lacking full block/error: {", ".join(non_compliant[:3])}{'...' if len(non_compliant) > 3 else ''}"

        return create_standard_response(
            CONTROL_ID, status, message,
            remediation='Enable all four S3 Block Public Access settings for each listed bucket.',
            remediation_available=True
        )
    except ClientError as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to list buckets or check settings: {str(e)}')


# --- Control Mapping ---

CONTROL_CHECK_MAP = {
    'Account.1': check_security_contact,
    'CloudTrail.1': check_cloudtrail_multi_region,
    'CloudTrail.2': check_cloudtrail_encryption,
    'Config.1': check_config_enabled,            # Added
    'EC2.6': check_vpc_flow_logs,                 # Added
    'EC2.7': check_ebs_encryption,
    'IAM.2': check_iam_user_policies,             # Added
    'IAM.3': check_iam_key_rotation,              # Added
    'IAM.4': check_root_access_keys,
    'IAM.9': check_root_mfa,
    'IAM.22': check_unused_credentials,           # Added
    'KMS.4': check_kms_rotation,                  # Added
    'S3.1': check_s3_block_public, # Covers S3.8 too
    # Add more checks here in future versions
}

# --- Main Lambda Handler ---

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main entry point for Lambda function. Handles 'evaluate' and 'remediate' actions.
    """
    # Ensure start_time is defined correctly
    start_time = time.time()
    logger.info(f"Received event: {json.dumps(event)}")

    action = event.get('action', 'evaluate')

    if action == 'evaluate':
        logger.info(f"Starting compliance evaluation (v0.6) for {len(CONTROL_CHECK_MAP)} controls...")
        results = []
        futures = {}

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            for control_id, check_function in CONTROL_CHECK_MAP.items():
                futures[executor.submit(check_function)] = control_id

            for future in as_completed(futures):
                control_id = futures[future]
                try:
                    result = future.result()
                    if result: # Ensure result is not None
                        # Add S3.8 result based on S3.1 check
                        if control_id == 'S3.1':
                             s3_8_result = result.copy()
                             s3_8_result['control'] = 'S3.8'
                             results.append(s3_8_result)
                        results.append(result)
                        logger.debug(f"Completed check for {control_id}: {result.get('status')}")
                    else:
                         logger.error(f"Check function for {control_id} returned None")
                         results.append(create_standard_response(control_id, 'ERROR', "Check function implementation error (returned None)."))

                except Exception as e:
                    logger.error(f"Unexpected error executing check for {control_id}: {e}", exc_info=True)
                    results.append(create_standard_response(control_id, 'ERROR', f"Check execution failed: {e}"))

        end_time = time.time()
        duration = end_time - start_time
        logger.info(f"Evaluation completed in {duration:.2f} seconds.")

        summary = {
            status: sum(1 for r in results if r.get('status') == status)
            for status in ['PASS', 'FAIL', 'ERROR']
        }
        report_key = f"report-v0.6-{int(time.time())}.json" # Updated version in key
        report_body = json.dumps({
            'report_metadata': {
                 'version': '0.6', # Updated version in report
                 'timestamp_utc': datetime.now(timezone.utc).isoformat(),
                 'duration_seconds': round(duration, 2),
                 'controls_evaluated': len(CONTROL_CHECK_MAP)
            },
            'summary': summary,
            'results': sorted(results, key=lambda x: x.get('control', '')) # Safer sort
        }, indent=2)

        # Upload report to S3 (Ensure REPORT_BUCKET is correctly set)
        if REPORT_BUCKET:
             try:
                  s3_client.put_object(
                       Bucket=REPORT_BUCKET,
                       Key=report_key,
                       Body=report_body,
                       ContentType='application/json'
                  )
                  logger.info(f"Successfully uploaded JSON report to s3://{REPORT_BUCKET}/{report_key}")
             except ClientError as e:
                  logger.error(f"Failed to upload report to S3 bucket {REPORT_BUCKET}: {e}", exc_info=True)
             except Exception as e:
                  logger.error(f"Unexpected error uploading report: {e}", exc_info=True)
        else:
             logger.warning("REPORT_BUCKET environment variable not set. Skipping report upload.")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'status': 'Evaluation Complete',
                'version': '0.6',
                'summary': summary,
                'report_bucket': REPORT_BUCKET or "Not Set",
                'report_key': report_key if REPORT_BUCKET else "N/A"
            })
        }

    elif action == 'remediate':
        logger.info("Remediation action requested (v0.6 - Not Implemented).")
        control_id = event.get('control_id')
        if not control_id:
            return {'statusCode': 400, 'body': json.dumps({'error': "Missing control_id for remediation"})}

        return {
            'statusCode': 501,
            'body': json.dumps({'message': f'Remediation for {control_id} not implemented in v0.6.'})
        }

    else:
        logger.error(f"Invalid action specified: {action}")
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Invalid action, must be evaluate or remediate'})
        }

# Example for local testing (if needed)
if __name__ == "__main__":
    print("Running local test evaluation (v0.6)...")
    test_event = {'action': 'evaluate'}
    result = lambda_handler(test_event, None)
    print("\n--- Lambda Response ---")
    print(json.dumps(result, indent=2)) 