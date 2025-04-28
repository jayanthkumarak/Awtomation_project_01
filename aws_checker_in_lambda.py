import json
import boto3
import time
import os
import logging
import csv
import io
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone, timedelta
from botocore.config import Config
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configuration from environment variables (Optional: Keep for logging/context)
REPORT_BUCKET = os.environ.get('REPORT_BUCKET', 'cis-compliance-reports')
BACKUP_BUCKET = os.environ.get('BACKUP_BUCKET', 'cis-compliance-backups') # Unused after removing remediation
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
logger.setLevel(LOG_LEVEL)

# Configure retry settings for AWS clients (will be used inside handler)
retry_config = Config(
    retries={'max_attempts': 3, 'mode': 'standard'}
)

# Define MAX_WORKERS for ThreadPoolExecutor
MAX_WORKERS = 10

# -------------------------------------------------------------------------
# AI Assistance Acknowledgment (Optional)
# -------------------------------------------------------------------------
# This Lambda function was developed with assistance from:
# - Claude 3.7 Sonnet: Optimized code structure, error handling, and AWS service integration
# - Grok 3: Contributed to security rule implementation and compliance logic
# - Gemini 2.5 Pro: Enhanced error handling and logging
#
# Together, these AI systems helped create a more robust, efficient, and
# secure AWS compliance checking solution.
# -------------------------------------------------------------------------


# --- Helper Functions ---

def create_standard_response(control_id: str, status: str, message: str, remediation: Optional[str] = None, remediation_available: bool = False) -> Dict[str, Any]:
    """Creates a standard dictionary structure for check results."""
    return {
        'control': control_id,
        'status': status,
        'message': message,
        'remediation': remediation if remediation is not None else "See control documentation.",
        'remediation_available': remediation_available # Kept for info, though remediation functions removed
    }

def paginate(client, method_name: str, result_key: str, **kwargs) -> List[Dict[str, Any]]:
    """Generic pagination helper for boto3 list/describe calls."""
    results = []
    try:
        paginator = client.get_paginator(method_name)
        for page in paginator.paginate(**kwargs):
            results.extend(page.get(result_key, []))
        return results
    except ClientError as e:
        if e.response['Error']['Code'] in ['AccessDeniedException', 'UnrecognizedClientException', 'InvalidClientTokenId']:
             logger.warning(f"Access denied or client error during pagination for {method_name} (Check permissions/region): {e}")
        else:
             logger.error(f"Pagination failed for {method_name} with args {kwargs}: {e}", exc_info=True)
        return [] # Return empty on error
    except Exception as e: # Catch other potential issues like non-existent paginator
        logger.error(f"Unexpected error during pagination setup or execution for {method_name}: {e}", exc_info=True)
        return []

def get_all_mfa_devices(iam_client, username: str) -> List[Dict[str, Any]]:
    """Retrieve all MFA devices for a specific user using manual pagination."""
    mfa_devices = []
    marker = None
    try:
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
        return []
    except Exception as e:
        logger.error(f"Unexpected error listing MFA devices for {username}: {e}", exc_info=True)
        return []

def get_all_attached_user_policies(iam_client, username: str) -> List[Dict[str, Any]]:
    """Retrieve all directly attached managed policies for a user using pagination."""
    try:
        # list_attached_user_policies uses standard boto3 pagination
        return paginate(iam_client, 'list_attached_user_policies', 'AttachedPolicies', UserName=username)
    except Exception as e:
        logger.error(f"Error paginating attached policies for user {username}: {e}", exc_info=True)
        return []

def _get_credential_report(iam_client) -> Optional[List[Dict]]:
    """Helper to get and parse the IAM credential report. Returns list of dicts or None."""
    try:
        iam_client.generate_credential_report()
        report_state = ''
        attempts = 0
        while report_state != 'COMPLETE' and attempts < 10: # Wait up to ~20 seconds
            report_info = iam_client.get_credential_report()
            report_state = report_info.get('State')
            if report_state == 'COMPLETE':
                content_bytes = report_info.get('Content')
                if not content_bytes:
                     logger.error("Credential report content is empty despite COMPLETE state.")
                     return None
                try:
                    content_string = content_bytes.decode('utf-8')
                    csv_reader = csv.DictReader(io.StringIO(content_string))
                    report_data = list(csv_reader) # Convert iterator to list
                    return report_data
                except (UnicodeDecodeError, csv.Error) as parse_e:
                     logger.error(f"Failed to decode or parse credential report CSV: {parse_e}", exc_info=True)
                     return None
                except Exception as read_e: # Catch other errors during read/parse
                     logger.error(f"Unexpected error reading/parsing credential report: {read_e}", exc_info=True)
                     return None
            elif report_state == 'FAILED':
                logger.error(f"Credential report generation failed: {report_info.get('Description')}")
                return None
            attempts += 1
            logger.info(f"Waiting for credential report generation... attempt {attempts}")
            time.sleep(2) # Wait before checking again

        logger.error("Credential report did not become available in time.")
        return None
    except ClientError as e:
        logger.error(f"ClientError getting/generating credential report: {e}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"Unexpected error getting credential report: {e}", exc_info=True)
        return None

# --- Control Check Functions ---

def check_security_contact(iam_client) -> Dict[str, Any]:
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
    except Exception as e:
        logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Unexpected error: {str(e)}')

def check_cloudtrail_enabled(cloudtrail_client) -> Dict[str, Any]:
    CONTROL_ID = 'CloudTrail.1'
    def logs_management_events(trail_name: str) -> bool:
        try:
            response = cloudtrail_client.get_event_selectors(TrailName=trail_name)
            selectors = response.get('EventSelectors', [])
            if selectors:
                for selector in selectors:
                    if selector.get('IncludeManagementEvents', False) and selector.get('ReadWriteType') == 'All':
                        return True
                return False
            advanced_selectors = response.get('AdvancedEventSelectors', [])
            if advanced_selectors:
                 logger.info(f"Trail {trail_name} uses Advanced Event Selectors. Assuming management events logged.")
                 return True
            insight_selectors = response.get('InsightSelectors', [])
            if insight_selectors:
                 logger.info(f"Trail {trail_name} uses Insight Selectors. Assuming management events logged.")
                 return True
            logger.warning(f"Trail {trail_name} has no standard, advanced, or insight selectors found.")
            return False
        except ClientError as e:
            if e.response['Error']['Code'] == 'TrailNotFoundException':
                 logger.warning(f"Trail {trail_name} not found when getting event selectors.")
            elif e.response['Error']['Code'] == 'UnsupportedOperationException':
                 logger.info(f"GetEventSelectors not supported for {trail_name}. Skipping selector check.")
                 return True
            else:
                 logger.warning(f"Failed to get event selectors for trail {trail_name}: {e}", exc_info=True)
            return False
    try:
        trails = paginate(cloudtrail_client, 'describe_trails', 'trailList')
        if not trails:
            return create_standard_response(CONTROL_ID, 'FAIL', "No CloudTrail trails found")
        multi_region_trails = [t for t in trails if t.get('IsMultiRegionTrail')]
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
                           # break # Uncomment if ONE compliant trail is enough
        status = 'PASS' if compliant_trail_found else 'FAIL'
        message = (
            f"Found {len(trails)} trail(s). {len(multi_region_trails)} are multi-region. "
            f"Checked {checked_trails_count} multi-region trail(s) for 'All' management event logging: {logging_ok_count} passed."
        )
        if status == 'FAIL' and not multi_region_trails:
             message += " No multi-region trails found."
        remediation = 'Ensure at least one multi-region trail logs all management events.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except Exception as e:
         error_message = f"Unexpected error during CloudTrail check: {str(e)}"
         logger.error(error_message, exc_info=True)
         return create_standard_response(CONTROL_ID, 'ERROR', error_message)

def check_cloudtrail_encryption(cloudtrail_client) -> Dict[str, Any]:
    CONTROL_ID = 'CloudTrail.2'
    try:
        trails = paginate(cloudtrail_client, 'describe_trails', 'trailList')
        if not trails:
             return create_standard_response(CONTROL_ID, 'PASS', 'No CloudTrail trails found.')
        non_encrypted = [t['Name'] for t in trails if not t.get('KmsKeyId')]
        status = 'PASS' if not non_encrypted else 'FAIL'
        message = f"{len(trails) - len(non_encrypted)}/{len(trails)} trails are encrypted with KMS."
        if non_encrypted:
             message += f" Non-encrypted: {', '.join(non_encrypted[:5])}{'...' if len(non_encrypted) > 5 else ''}"
        remediation = 'Enable KMS encryption on non-encrypted trails.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except Exception as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_cloudtrail_validation(cloudtrail_client) -> Dict[str, Any]:
    CONTROL_ID = 'CloudTrail.4'
    try:
        trails = paginate(cloudtrail_client, 'describe_trails', 'trailList')
        if not trails:
            return create_standard_response(CONTROL_ID, 'PASS', "No CloudTrail trails found.")
        no_validation = [t['Name'] for t in trails if not t.get('LogFileValidationEnabled')]
        status = 'PASS' if not no_validation else 'FAIL'
        message = f"{len(trails) - len(no_validation)}/{len(trails)} trails have log validation enabled."
        if no_validation:
             message += f" Lacking validation: {', '.join(no_validation[:5])}{'...' if len(no_validation) > 5 else ''}"
        remediation = 'Enable log file validation on trails lacking it.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except Exception as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_config_enabled(config_client) -> Dict[str, Any]:
    CONTROL_ID = 'Config.1'
    try:
        recorders = paginate(config_client, 'describe_configuration_recorders', 'ConfigurationRecorders')
        is_enabled = False
        status_msg = 'Config is not enabled (no recorders found).'
        if recorders:
             status_msg = 'Config recorder found but may not be recording or status unknown.'
             try:
                  status_resp = config_client.describe_configuration_recorder_status(ConfigurationRecorderNames=[recorders[0]['name']])
                  if status_resp.get('ConfigurationRecordersStatus') and status_resp['ConfigurationRecordersStatus'][0].get('recording'):
                       is_enabled = True
                       status_msg = 'Config enabled and recorder is recording.'
             except ClientError as status_e:
                  logger.warning(f"Could not get status for config recorder {recorders[0].get('name')}: {status_e}")
                  is_enabled = True # Assume enabled if recorder exists but status check fails
        final_status = 'PASS' if is_enabled else 'FAIL'
        remediation = 'Enable AWS Config and start the configuration recorder in this region.' if final_status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, final_status, status_msg, remediation=remediation, remediation_available=(final_status == 'FAIL'))
    except ClientError as e:
         logger.warning(f"Error checking AWS Config (potential service/permission issue): {e}")
         return create_standard_response(CONTROL_ID, 'FAIL', f'Config not enabled or error checking: {str(e)}', remediation='Enable AWS Config', remediation_available=True)
    except Exception as e:
         logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
         return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_vpc_default_sg(ec2_client) -> Dict[str, Any]:
    CONTROL_ID = 'EC2.2'
    try:
        sgs = paginate(ec2_client, 'describe_security_groups', 'SecurityGroups')
        if not sgs: # Paginate returns [] on error or if none exist
             logger.warning(f"Could not retrieve security groups for {CONTROL_ID} check.")
             # Can't determine status without data, return ERROR
             return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve Security Group data.")
        default_sgs = [sg for sg in sgs if sg.get('GroupName') == 'default']
        if not default_sgs:
             return create_standard_response(CONTROL_ID, 'PASS', "No default security groups found.")
        non_compliant = []
        for sg in default_sgs:
            if sg.get('IpPermissions'): # Check for any inbound rules
                non_compliant.append(sg['GroupId'])
                continue # Already non-compliant
            # Check egress rules
            has_non_default_egress = False
            egress_rules = sg.get('IpPermissionsEgress', [])
            allowed_egress_signature = [
                 # Allow only IPv4 All
                 ({'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}),
                 # Allow only IPv6 All
                 ({'IpProtocol': '-1', 'Ipv6Ranges': [{'CidrIpv6': '::/0'}]}),
                 # Allow both IPv4 and IPv6 All in one rule definition
                 ({'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'Ipv6Ranges': [{'CidrIpv6': '::/0'}]})
            ]
            # Check if the set of egress rules exactly matches one of the allowed signatures
            # This requires normalizing the rule structure from the API response
            normalized_egress = []
            for rule in egress_rules:
                 norm_rule = {'IpProtocol': rule.get('IpProtocol')}
                 if rule.get('IpRanges'): norm_rule['IpRanges'] = rule['IpRanges']
                 if rule.get('Ipv6Ranges'): norm_rule['Ipv6Ranges'] = rule['Ipv6Ranges']
                 # Ignore UserIdGroupPairs and PrefixListIds if they are empty
                 if rule.get('UserIdGroupPairs'): norm_rule['UserIdGroupPairs'] = rule['UserIdGroupPairs']
                 if rule.get('PrefixListIds'): norm_rule['PrefixListIds'] = rule['PrefixListIds']
                 normalized_egress.append(norm_rule)

            # Simplification: Check if *any* rule is NOT in the simple allowed list (ignoring combined rule case for now)
            simple_allowed = [
                {'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                {'IpProtocol': '-1', 'Ipv6Ranges': [{'CidrIpv6': '::/0'}]}
            ]
            for rule in normalized_egress:
                is_simple_allowed = False
                for allowed in simple_allowed:
                    # Check if the keys in allowed are a subset of rule and values match
                    match = True
                    for k, v in allowed.items():
                        if rule.get(k) != v:
                            match = False
                            break
                    if match:
                        is_simple_allowed = True
                        break
                if not is_simple_allowed:
                    has_non_default_egress = True
                    break

            if has_non_default_egress:
                 non_compliant.append(sg['GroupId'])

        status = 'PASS' if not non_compliant else 'FAIL'
        message = f"{len(default_sgs) - len(non_compliant)}/{len(default_sgs)} default SGs restrict traffic appropriately."
        if non_compliant:
             message += f" Default SGs with disallowed rules: {', '.join(list(set(non_compliant))[:5])}{'...' if len(set(non_compliant)) > 5 else ''}"
        remediation = 'Remove all inbound rules and non-standard outbound rules from default SGs.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except Exception as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_vpc_flow_logs(ec2_client) -> Dict[str, Any]:
    CONTROL_ID = 'EC2.6'
    try:
        flow_logs = paginate(ec2_client, 'describe_flow_logs', 'FlowLogs')
        active_logs_count = sum(1 for log in flow_logs if log.get('FlowLogStatus') == 'ACTIVE')
        status = 'PASS' if active_logs_count > 0 else 'FAIL'
        message = f"Found {len(flow_logs)} VPC flow log(s), {active_logs_count} are ACTIVE."
        if not flow_logs:
             message = "No VPC flow logs found."
        elif active_logs_count == 0:
             message += " None are currently ACTIVE."
        remediation = 'Enable VPC flow logs for VPCs and ensure they are in the ACTIVE state.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except ClientError as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')
    except Exception as e:
         logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
         return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_ebs_encryption(ec2_client) -> Dict[str, Any]:
    CONTROL_ID = 'EC2.7'
    try:
        response = ec2_client.get_ebs_encryption_by_default()
        is_enabled = response.get('EbsEncryptionByDefault', False)
        status = 'PASS' if is_enabled else 'FAIL'
        message = f"EBS default encryption is {'enabled' if is_enabled else 'disabled'} in this region."
        remediation = 'Enable EBS default encryption in EC2 settings for this region.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except ClientError as e:
        if e.response['Error']['Code'] == 'UnsupportedOperation':
             logger.warning(f"{CONTROL_ID}: EBS default encryption setting not supported/checkable in this region.")
             return create_standard_response(CONTROL_ID, 'PASS', 'EBS default encryption setting not supported/checkable in this region.') # Treat as PASS/NA
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')
    except Exception as e:
         logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
         return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_imdsv2(ec2_client) -> Dict[str, Any]:
    CONTROL_ID = 'EC2.8'
    try:
        reservations = paginate(ec2_client, 'describe_instances', 'Reservations')
        non_compliant = []
        instance_count = 0
        active_instance_count = 0
        for r in reservations:
            for instance in r.get('Instances', []):
                instance_count += 1
                instance_state = instance.get('State', {}).get('Name', 'unknown')
                if instance_state not in ['terminated', 'shutting-down']:
                    active_instance_count += 1
                    metadata_options = instance.get('MetadataOptions', {})
                    if metadata_options.get('HttpTokens') != 'required':
                        non_compliant.append(instance['InstanceId'])
        status = 'PASS' if not non_compliant else 'FAIL'
        message = f"{active_instance_count - len(non_compliant)}/{active_instance_count} active instances enforce IMDSv2."
        if non_compliant:
            message += f" Instances not enforcing IMDSv2: {', '.join(non_compliant[:5])}{'...' if len(non_compliant) > 5 else ''}"
        elif active_instance_count == 0:
             message = "No active EC2 instances found."
             status = 'PASS'
        remediation = 'Modify instance metadata options to require HttpTokens (IMDSv2).' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except Exception as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_nacl_open_ports(ec2_client) -> Dict[str, Any]:
    CONTROL_ID = 'EC2.21'
    admin_ports = {22, 3389}
    try:
        nacls = paginate(ec2_client, 'describe_network_acls', 'NetworkAcls')
        open_nacls = []
        for n in nacls:
            for e in n.get('Entries', []):
                 # Check IPv4 ingress rule allowing admin ports from anywhere
                if e.get('Egress') == False and e.get('RuleAction') == 'allow' and e.get('CidrBlock') == '0.0.0.0/0':
                    port_range = e.get('PortRange', {})
                    from_port = port_range.get('From')
                    to_port = port_range.get('To')
                    # Check if rule applies to TCP (6) or All Protocols (-1)
                    if str(e.get('Protocol')) in ['6', '-1'] and from_port is not None and to_port is not None:
                        try:
                            rule_ports = set(range(int(from_port), int(to_port) + 1))
                            if not admin_ports.isdisjoint(rule_ports):
                                open_nacls.append(n['NetworkAclId'])
                                break # Found violation for this NACL, move to next
                        except ValueError:
                            logger.warning(f"Could not parse port range {from_port}-{to_port} for NACL {n['NetworkAclId']}")
            if n['NetworkAclId'] in open_nacls: continue # Avoid checking IPv6 if already failed on IPv4

            # Check IPv6 ingress rule allowing admin ports from anywhere
            for e in n.get('Entries', []):
                 if e.get('Egress') == False and e.get('RuleAction') == 'allow' and e.get('Ipv6CidrBlock') == '::/0':
                     port_range = e.get('PortRange', {})
                     from_port = port_range.get('From')
                     to_port = port_range.get('To')
                     if str(e.get('Protocol')) in ['6', '-1'] and from_port is not None and to_port is not None:
                         try:
                             rule_ports = set(range(int(from_port), int(to_port) + 1))
                             if not admin_ports.isdisjoint(rule_ports):
                                 open_nacls.append(n['NetworkAclId'])
                                 break
                         except ValueError:
                             logger.warning(f"Could not parse port range {from_port}-{to_port} for NACL {n['NetworkAclId']}")
        unique_open_nacls = sorted(list(set(open_nacls)))
        status = 'PASS' if not unique_open_nacls else 'FAIL'
        message = f"{len(unique_open_nacls)} NACLs found allowing unrestricted ingress to admin ports (22, 3389)."
        if unique_open_nacls:
             message += f" Offending NACLs: {', '.join(unique_open_nacls[:5])}{'...' if len(unique_open_nacls) > 5 else ''}"
        remediation = 'Modify NACL rules to restrict access to ports 22 and 3389.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except ClientError as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')
    except Exception as e:
         logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
         return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_sg_open_ipv4(ec2_client) -> Dict[str, Any]:
    CONTROL_ID = 'EC2.53'
    admin_ports = {22, 3389}
    open_ipv4 = '0.0.0.0/0'
    try:
        sgs = paginate(ec2_client, 'describe_security_groups', 'SecurityGroups')
        open_groups = []
        checked_sg_count = 0
        for sg in sgs:
            sg_id = sg['GroupId']
            sg_name = sg.get('GroupName')
            if sg_name == 'default': continue # Skip default SG (covered by EC2.2)
            checked_sg_count += 1
            for p in sg.get('IpPermissions', []):
                from_port = p.get('FromPort')
                to_port = p.get('ToPort')
                ip_protocol = p.get('IpProtocol', '')
                port_match = False
                if from_port is not None and to_port is not None and ip_protocol.lower() in ['tcp', '6', '-1']:
                    try:
                        rule_ports = set(range(int(from_port), int(to_port) + 1))
                        if not admin_ports.isdisjoint(rule_ports): port_match = True
                    except ValueError: logger.warning(f"Invalid port range in SG {sg_id}: {from_port}-{to_port}")
                elif ip_protocol == '-1': port_match = True
                open_from_anywhere = any(r.get('CidrIp') == open_ipv4 for r in p.get('IpRanges', []))
                if port_match and open_from_anywhere:
                    open_groups.append(sg_id)
                    break # Check next SG
        unique_open_groups = sorted(list(set(open_groups)))
        status = 'PASS' if not unique_open_groups else 'FAIL'
        message = f"{len(unique_open_groups)}/{checked_sg_count} non-default SGs allow unrestricted IPv4 ingress to admin ports (22, 3389)."
        if unique_open_groups: message += f" Offending SGs: {', '.join(unique_open_groups[:5])}{'...' if len(unique_open_groups) > 5 else ''}"
        remediation = 'Modify SG rules to restrict IPv4 ingress from 0.0.0.0/0 to ports 22/3389.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except Exception as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_sg_open_ipv6(ec2_client) -> Dict[str, Any]:
    CONTROL_ID = 'EC2.54'
    admin_ports = {22, 3389}
    open_ipv6 = '::/0'
    try:
        sgs = paginate(ec2_client, 'describe_security_groups', 'SecurityGroups')
        open_groups = []
        checked_sg_count = 0
        for sg in sgs:
            sg_id = sg['GroupId']
            sg_name = sg.get('GroupName')
            if sg_name == 'default': continue
            checked_sg_count += 1
            for p in sg.get('IpPermissions', []):
                from_port = p.get('FromPort')
                to_port = p.get('ToPort')
                ip_protocol = p.get('IpProtocol', '')
                port_match = False
                if from_port is not None and to_port is not None and ip_protocol.lower() in ['tcp', '6', '-1']:
                    try:
                        rule_ports = set(range(int(from_port), int(to_port) + 1))
                        if not admin_ports.isdisjoint(rule_ports): port_match = True
                    except ValueError: logger.warning(f"Invalid port range in SG {sg_id}: {from_port}-{to_port}")
                elif ip_protocol == '-1': port_match = True
                open_from_anywhere = any(r.get('CidrIpv6') == open_ipv6 for r in p.get('Ipv6Ranges', []))
                if port_match and open_from_anywhere:
                    open_groups.append(sg_id)
                    break
        unique_open_groups = sorted(list(set(open_groups)))
        status = 'PASS' if not unique_open_groups else 'FAIL'
        message = f"{len(unique_open_groups)}/{checked_sg_count} non-default SGs allow unrestricted IPv6 ingress to admin ports (22, 3389)."
        if unique_open_groups: message += f" Offending SGs: {', '.join(unique_open_groups[:5])}{'...' if len(unique_open_groups) > 5 else ''}"
        remediation = 'Modify SG rules to restrict IPv6 ingress from ::/0 to ports 22/3389.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except Exception as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_efs_encryption(efs_client) -> Dict[str, Any]:
    CONTROL_ID = 'EFS.1'
    try:
        fs = paginate(efs_client, 'describe_file_systems', 'FileSystems')
        if not fs:
             return create_standard_response(CONTROL_ID, 'PASS', "No EFS file systems found.")
        unencrypted = [f['FileSystemId'] for f in fs if not f.get('Encrypted')]
        status = 'PASS' if not unencrypted else 'FAIL'
        message = f"{len(fs) - len(unencrypted)}/{len(fs)} EFS file systems are encrypted."
        if unencrypted:
             message += f" Unencrypted: {', '.join(unencrypted[:5])}{'...' if len(unencrypted) > 5 else ''}"
        remediation = 'Recreate EFS with encryption enabled (manual process).' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=False) # Always manual
    except Exception as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_iam_user_policies(iam_client) -> Dict[str, Any]:
    CONTROL_ID = 'IAM.2'
    try:
        users = paginate(iam_client, 'list_users', 'Users')
        if not users:
            return create_standard_response(CONTROL_ID, 'PASS', "No IAM users found.")
        with_policies = []
        users_checked = 0
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
             future_to_user = {executor.submit(get_all_attached_user_policies, iam_client, u['UserName']): u['UserName'] for u in users}
             for future in as_completed(future_to_user):
                 username = future_to_user[future]
                 users_checked += 1
                 try:
                     attached_policies = future.result()
                     if attached_policies:
                         with_policies.append(username)
                 except Exception as e:
                     logger.warning(f"Error checking attached policies for user {username}: {e}", exc_info=True)
                     users_checked -=1 # Don't count if check failed
        status = 'PASS' if not with_policies else 'FAIL'
        message = f"{users_checked - len(with_policies)}/{users_checked} users checked do not have direct policies."
        if with_policies:
            message += f" Users with direct policies: {', '.join(with_policies[:5])}{'...' if len(with_policies) > 5 else ''}"
        remediation = 'Move policies from users to IAM groups (manual process).' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=False) # Always manual
    except Exception as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_iam_key_rotation(iam_client) -> Dict[str, Any]:
    CONTROL_ID = 'IAM.3'
    MAX_KEY_AGE_DAYS = 90
    try:
        report_data = _get_credential_report(iam_client)
        if report_data is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Could not retrieve or parse IAM credential report.", False)
        old_keys = []
        now = datetime.now(timezone.utc)
        user_count = 0
        active_key_count = 0
        for row in report_data:
            try:
                username = row.get('user')
                if not username or username == '<root_account>': continue
                user_count += 1
                for key_num in ['1', '2']:
                    key_active = row.get(f'access_key_{key_num}_active') == 'true'
                    if key_active:
                        active_key_count += 1
                        last_rotated_str = row.get(f'access_key_{key_num}_last_rotated')
                        if last_rotated_str and last_rotated_str != 'N/A':
                            try:
                                last_rotated = datetime.fromisoformat(last_rotated_str.replace('Z', '+00:00'))
                                key_age = (now - last_rotated).days
                                if key_age >= MAX_KEY_AGE_DAYS:
                                    old_keys.append(f"{username} (key {key_num}, age {key_age} days)")
                            except ValueError:
                                 logger.warning(f"Could not parse key{key_num} rotation date '{last_rotated_str}' for {username}")
                                 old_keys.append(f"{username} (key {key_num}, invalid rotation date)")
                        else: # Active key, never rotated
                            creation_str = row.get('user_creation_time')
                            age_desc = "never rotated"
                            if creation_str and creation_str != 'N/A':
                                try:
                                    creation_date = datetime.fromisoformat(creation_str.replace('Z', '+00:00'))
                                    if (now - creation_date).days >= MAX_KEY_AGE_DAYS:
                                        age_desc = f"never rotated, user age {(now - creation_date).days} days"
                                except ValueError: pass
                            old_keys.append(f"{username} (key {key_num}, {age_desc})")
            except Exception as parse_e:
                 logger.warning(f"Skipping report row due to processing error: {parse_e}. Row sample: {str(row)[:100]}...", exc_info=True)
                 continue
        unique_old_keys = sorted(list(set(old_keys)))
        status = 'PASS' if not unique_old_keys else 'FAIL'
        message = f"{active_key_count - len(unique_old_keys)}/{active_key_count} active IAM user keys rotated within {MAX_KEY_AGE_DAYS} days."
        if unique_old_keys: message += f" Keys needing rotation: {', '.join(unique_old_keys[:5])}{'...' if len(unique_old_keys) > 5 else ''}"
        elif user_count == 0: message = "No IAM users found in credential report (excluding root)."; status = 'PASS'
        elif active_key_count == 0: message = "No active IAM user access keys found."; status = 'PASS'
        remediation = f'Rotate IAM user access keys older than {MAX_KEY_AGE_DAYS} days (manual process).' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=False) # Always manual
    except Exception as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_root_access_keys(iam_client) -> Dict[str, Any]:
    CONTROL_ID = 'IAM.4'
    try:
        summary_map = iam_client.get_account_summary().get('SummaryMap', {})
        if not summary_map:
            return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve account summary data.", False)
        keys_present = summary_map.get('AccountAccessKeysPresent', 0)
        status = 'PASS' if keys_present in [0, 2] else 'FAIL'
        message = f"Root account access keys found: {keys_present == 1}."
        remediation = 'Delete root account access keys (manual process).' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=False)
    except Exception as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_iam_mfa_console(iam_client) -> Dict[str, Any]:
    CONTROL_ID = 'IAM.5'
    try:
        users = paginate(iam_client, 'list_users', 'Users')
        if not users:
            return create_standard_response(CONTROL_ID, 'PASS', "No IAM users found.")
        no_mfa = []
        checked_users = 0
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
             future_to_user = {}
             for u in users:
                 if u.get('PasswordLastUsed'): # Simple check for console access potential
                     username = u['UserName']
                     future_to_user[executor.submit(get_all_mfa_devices, iam_client, username)] = username
             for future in as_completed(future_to_user):
                 username = future_to_user[future]
                 checked_users += 1
                 try:
                     mfa_devices = future.result()
                     if not mfa_devices:
                         no_mfa.append(username)
                 except Exception as e:
                      logger.warning(f"Error checking MFA for user {username}: {e}", exc_info=True)
                      checked_users -= 1 # Don't count if check failed
        status = 'PASS' if not no_mfa else 'FAIL'
        message = f"{checked_users - len(no_mfa)}/{checked_users} console users checked have MFA enabled."
        if no_mfa: message += f" Console users lacking MFA: {', '.join(no_mfa[:5])}{'...' if len(no_mfa) > 5 else ''}"
        elif checked_users == 0: message = "No IAM users found with console passwords or checks failed."; status = 'PASS'
        remediation = 'Enable MFA for IAM console users (manual process).' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=False) # Manual
    except Exception as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_root_mfa(iam_client) -> Dict[str, Any]:
    CONTROL_ID = 'IAM.9'
    try:
        summary_map = iam_client.get_account_summary().get('SummaryMap', {})
        if not summary_map:
            return create_standard_response(CONTROL_ID, 'ERROR', "Failed to retrieve account summary data.", False)
        mfa_enabled = summary_map.get('AccountMFAEnabled', 0)
        status = 'PASS' if mfa_enabled == 1 else 'FAIL'
        message = f"Root account MFA enabled: {mfa_enabled == 1}."
        remediation = 'Enable MFA for root account (manual process).' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=False)
    except Exception as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_password_length(iam_client) -> Dict[str, Any]:
    CONTROL_ID = 'IAM.15'
    MIN_LENGTH = 14
    try:
        policy = iam_client.get_account_password_policy().get('PasswordPolicy')
        current_length = policy.get('MinimumPasswordLength', 0)
        status = 'PASS' if current_length >= MIN_LENGTH else 'FAIL'
        message = f"Password policy minimum length is {current_length} (required >= {MIN_LENGTH})."
        remediation = f'Set password policy minimum length to {MIN_LENGTH} or greater.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except ClientError as e:
         if e.response['Error']['Code'] == 'NoSuchEntity':
              return create_standard_response(CONTROL_ID, 'FAIL', "No IAM password policy defined.", remediation=f'Set password policy minimum length to {MIN_LENGTH} or greater.', remediation_available=True)
         else:
              logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
              return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')
    except Exception as e:
        logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_password_reuse(iam_client) -> Dict[str, Any]:
    CONTROL_ID = 'IAM.16'
    MIN_REUSE_PREVENTION = 1
    try:
        policy = iam_client.get_account_password_policy().get('PasswordPolicy')
        reuse_prevention = policy.get('PasswordReusePrevention', 0)
        status = 'PASS' if reuse_prevention >= MIN_REUSE_PREVENTION else 'FAIL'
        message = f"Password policy reuse prevention is set to {reuse_prevention} (required >= {MIN_REUSE_PREVENTION})."
        remediation = f'Configure password policy reuse prevention (at least {MIN_REUSE_PREVENTION}).' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except ClientError as e:
         if e.response['Error']['Code'] == 'NoSuchEntity':
             return create_standard_response(CONTROL_ID, 'FAIL', "No IAM password policy defined.", remediation=f'Configure password policy reuse prevention (at least {MIN_REUSE_PREVENTION}).', remediation_available=True)
         else:
             logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
             return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')
    except Exception as e:
        logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_support_role(iam_client) -> Dict[str, Any]:
    CONTROL_ID = 'IAM.18'
    SUPPORT_ROLE_PATTERN = 'Support'
    try:
        roles = paginate(iam_client, 'list_roles', 'Roles')
        support_role_found = any(SUPPORT_ROLE_PATTERN.lower() in r.get('RoleName', '').lower() for r in roles)
        status = 'PASS' if support_role_found else 'FAIL'
        message = f"IAM role for support access found: {support_role_found}."
        remediation = 'Create an IAM role for AWS support access.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except ClientError as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')
    except Exception as e:
        logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_unused_credentials(iam_client) -> Dict[str, Any]:
    CONTROL_ID = 'IAM.22'
    UNUSED_DAYS = 45
    try:
        report_data = _get_credential_report(iam_client)
        if report_data is None:
            return create_standard_response(CONTROL_ID, 'ERROR', "Could not retrieve or parse IAM credential report.", False)
        unused_creds = []
        now = datetime.now(timezone.utc)
        threshold_delta = timedelta(days=UNUSED_DAYS)
        user_count = 0
        active_creds_count = 0
        for row in report_data:
            try:
                username = row.get('user')
                if not username or username == '<root_account>': continue
                user_count += 1
                # Check Password
                password_enabled = row.get('password_enabled') == 'true'
                if password_enabled:
                     active_creds_count += 1
                     password_last_used_str = row.get('password_last_used')
                     is_unused = True
                     if password_last_used_str and password_last_used_str not in ['N/A', 'no_information']:
                          try:
                               password_last_used = datetime.fromisoformat(password_last_used_str.replace('Z', '+00:00'))
                               if now - password_last_used < threshold_delta: is_unused = False
                          except ValueError: logger.warning(f"Could not parse password_last_used date '{password_last_used_str}' for {username}")
                     elif password_last_used_str in ['N/A', 'no_information']: # Never used
                          user_creation_str = row.get('user_creation_time')
                          if user_creation_str and user_creation_str != 'N/A':
                               try:
                                    user_creation = datetime.fromisoformat(user_creation_str.replace('Z', '+00:00'))
                                    if now - user_creation < threshold_delta: is_unused = False # Created recently
                               except ValueError: pass
                     if is_unused: unused_creds.append(f"{username} (password)")
                # Check Access Keys
                for key_num in ['1', '2']:
                    key_active = row.get(f'access_key_{key_num}_active') == 'true'
                    if key_active:
                        active_creds_count += 1
                        key_last_used_str = row.get(f'access_key_{key_num}_last_used_date')
                        is_unused = True
                        if key_last_used_str and key_last_used_str not in ['N/A', 'no_information']:
                            try:
                                key_last_used = datetime.fromisoformat(key_last_used_str.replace('Z', '+00:00'))
                                if now - key_last_used < threshold_delta: is_unused = False
                            except ValueError: logger.warning(f"Could not parse key{key_num}_last_used date '{key_last_used_str}' for {username}")
                        elif key_last_used_str in ['N/A', 'no_information']: # Key active but never used
                            key_last_rotated_str = row.get(f'access_key_{key_num}_last_rotated')
                            if key_last_rotated_str and key_last_rotated_str != 'N/A':
                                try:
                                    key_last_rotated = datetime.fromisoformat(key_last_rotated_str.replace('Z', '+00:00'))
                                    if now - key_last_rotated < threshold_delta: is_unused = False # Key rotated recently
                                except ValueError: pass
                        if is_unused: unused_creds.append(f"{username} (key {key_num})")
            except Exception as parse_e:
                logger.warning(f"Skipping report row due to processing error: {parse_e}. Row sample: {str(row)[:100]}...", exc_info=True)
                continue
        unique_unused_creds = sorted(list(set(unused_creds)))
        status = 'PASS' if not unique_unused_creds else 'FAIL'
        message = f"{active_creds_count - len(unique_unused_creds)}/{active_creds_count} active credentials used within {UNUSED_DAYS} days."
        if unique_unused_creds: message += f" Credentials unused >= {UNUSED_DAYS} days: {', '.join(unique_unused_creds[:5])}{'...' if len(unique_unused_creds) > 5 else ''}"
        elif user_count == 0: message = "No IAM users found (excluding root)."; status = 'PASS'
        elif active_creds_count == 0: message = "No active IAM user credentials found."; status = 'PASS'
        remediation = f'Deactivate or remove IAM credentials unused for {UNUSED_DAYS} days or more (manual process).' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=False) # Manual
    except Exception as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_expired_certificates(iam_client) -> Dict[str, Any]:
    CONTROL_ID = 'IAM.26'
    try:
        certs_metadata = paginate(iam_client, 'list_server_certificates', 'ServerCertificateMetadataList')
        if not certs_metadata:
             return create_standard_response(CONTROL_ID, 'PASS', "No IAM server certificates found.")
        now = datetime.now(timezone.utc)
        expired_certs = [c['ServerCertificateName'] for c in certs_metadata if c.get('Expiration') and c['Expiration'] < now]
        status = 'PASS' if not expired_certs else 'FAIL'
        message = f"{len(certs_metadata) - len(expired_certs)}/{len(certs_metadata)} IAM server certificates are valid."
        if expired_certs: message += f" Expired certificates: {', '.join(expired_certs[:5])}{'...' if len(expired_certs) > 5 else ''}"
        remediation = 'Remove expired IAM server certificates.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except ClientError as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')
    except Exception as e:
        logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_cloudshell_policy(iam_client) -> Dict[str, Any]:
    CONTROL_ID = 'IAM.27'
    POLICY_ARN = 'arn:aws:iam::aws:policy/AWSCloudShellFullAccess'
    entities_found = {'users': [], 'groups': [], 'roles': []}
    total_entities = 0
    try:
        paginator = iam_client.get_paginator('list_entities_for_policy')
        pages = paginator.paginate(PolicyArn=POLICY_ARN, EntityFilter='All')
        for page in pages:
            entities_found['users'].extend([u['UserName'] for u in page.get('PolicyUsers', [])])
            entities_found['groups'].extend([g['GroupName'] for g in page.get('PolicyGroups', [])])
            entities_found['roles'].extend([r['RoleName'] for r in page.get('PolicyRoles', [])])
        total_entities = len(entities_found['users']) + len(entities_found['groups']) + len(entities_found['roles'])
        status = 'PASS' if total_entities == 0 else 'FAIL'
        message = f"{total_entities} entities found with AWSCloudShellFullAccess attached."
        if total_entities > 0:
             details = []
             if entities_found['users']: details.append(f"Users: {entities_found['users'][:2]}...")
             if entities_found['groups']: details.append(f"Groups: {entities_found['groups'][:2]}...")
             if entities_found['roles']: details.append(f"Roles: {entities_found['roles'][:2]}...")
             message += f" Details (truncated): {'; '.join(details)}"
        remediation = 'Detach the AWSCloudShellFullAccess policy from IAM users, groups, and roles.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=False) # Manual
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
             logger.info(f"Policy {POLICY_ARN} not found. Control {CONTROL_ID} passes.")
             return create_standard_response(CONTROL_ID, 'PASS', f"Policy {POLICY_ARN} not found.")
        else:
             logger.error(f"Error listing entities for policy {POLICY_ARN}: {e}", exc_info=True)
             return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check policy attachments for {POLICY_ARN}: {str(e)}')
    except Exception as e:
         logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
         return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_access_analyzer(iam_client) -> Dict[str, Any]:
    CONTROL_ID = 'IAM.28'
    try:
        analyzers = paginate(iam_client, 'list_analyzers', 'analyzers')
        active_analyzers = [a for a in analyzers if a.get('status') == 'ACTIVE']
        status = 'PASS' if active_analyzers else 'FAIL'
        message = f"Found {len(analyzers)} IAM Access Analyzer(s). {len(active_analyzers)} are ACTIVE in this region."
        if not analyzers: message = "No IAM Access Analyzers found in this region."
        elif not active_analyzers: message += " None are currently ACTIVE."
        remediation = 'Enable IAM Access Analyzer in this AWS region.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except ClientError as e:
        logger.error(f"Error listing Access Analyzers: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')
    except Exception as e:
         logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
         return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_kms_rotation(kms_client) -> Dict[str, Any]:
    CONTROL_ID = 'KMS.4'
    try:
        keys = paginate(kms_client, 'list_keys', 'Keys')
        if not keys:
            return create_standard_response(CONTROL_ID, 'PASS', "No KMS keys found.")
        keys_without_rotation = []
        cmk_checked_count = 0
        futures = {}
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_key = {executor.submit(kms_client.get_key_rotation_status, KeyId=k['KeyId']): k['KeyId'] for k in keys}
            for future in as_completed(future_to_key):
                key_id = future_to_key[future]
                try:
                    rotation_status = future.result()
                    cmk_checked_count += 1
                    if not rotation_status.get('KeyRotationEnabled'):
                        keys_without_rotation.append(key_id)
                except ClientError as e:
                    if e.response['Error']['Code'] in ['AccessDeniedException', 'UnsupportedOperationException', 'NotFoundException', 'KMSInvalidStateException']:
                         logger.debug(f"Skipping rotation check for key {key_id}: {e.response['Error']['Code']}")
                    else:
                         logger.warning(f"Error getting rotation status for KMS key {key_id}: {e}", exc_info=True)
                         keys_without_rotation.append(f"{key_id} (Error)")
        status = 'PASS' if not keys_without_rotation else 'FAIL'
        message = f"{cmk_checked_count - len(keys_without_rotation)}/{cmk_checked_count} checkable KMS keys have rotation enabled."
        if keys_without_rotation: message += f" Keys needing rotation (or error): {', '.join(keys_without_rotation[:3])}{'...' if len(keys_without_rotation) > 3 else ''}"
        elif cmk_checked_count == 0: message = "No checkable Customer Managed KMS keys found."; status = 'PASS'
        remediation = 'Enable annual key rotation for Customer Managed KMS keys.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except ClientError as e:
        logger.error(f"Error listing keys for {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to list keys: {str(e)}')
    except Exception as e:
        logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_rds_public(rds_client) -> Dict[str, Any]:
    CONTROL_ID = 'RDS.2'
    try:
        dbs = paginate(rds_client, 'describe_db_instances', 'DBInstances')
        if not dbs:
            return create_standard_response(CONTROL_ID, 'PASS', "No RDS instances found.")
        public_dbs = [db['DBInstanceIdentifier'] for db in dbs if db.get('PubliclyAccessible')]
        status = 'PASS' if not public_dbs else 'FAIL'
        message = f"{len(dbs) - len(public_dbs)}/{len(dbs)} RDS instances are not publicly accessible."
        if public_dbs: message += f" Publicly accessible RDS instances: {', '.join(public_dbs[:5])}{'...' if len(public_dbs) > 5 else ''}"
        remediation = 'Disable public access on RDS instances.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except Exception as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_rds_encryption(rds_client) -> Dict[str, Any]:
    CONTROL_ID = 'RDS.3'
    try:
        dbs = paginate(rds_client, 'describe_db_instances', 'DBInstances')
        if not dbs:
            return create_standard_response(CONTROL_ID, 'PASS', "No RDS instances found.")
        unencrypted = [db['DBInstanceIdentifier'] for db in dbs if not db.get('StorageEncrypted')]
        status = 'PASS' if not unencrypted else 'FAIL'
        message = f"{len(dbs) - len(unencrypted)}/{len(dbs)} RDS instances have storage encryption."
        if unencrypted: message += f" Unencrypted RDS instances: {', '.join(unencrypted[:5])}{'...' if len(unencrypted) > 5 else ''}"
        remediation = 'Recreate RDS instance with encryption enabled (manual process).' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=False) # Manual
    except Exception as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_rds_auto_upgrades(rds_client) -> Dict[str, Any]:
    CONTROL_ID = 'RDS.13'
    try:
        dbs = paginate(rds_client, 'describe_db_instances', 'DBInstances')
        if not dbs:
            return create_standard_response(CONTROL_ID, 'PASS', "No RDS instances found.")
        no_upgrade = [db['DBInstanceIdentifier'] for db in dbs if not db.get('AutoMinorVersionUpgrade')]
        status = 'PASS' if not no_upgrade else 'FAIL'
        message = f"{len(dbs) - len(no_upgrade)}/{len(dbs)} RDS instances have auto minor version upgrades enabled."
        if no_upgrade: message += f" RDS instances lacking auto upgrades: {', '.join(no_upgrade[:5])}{'...' if len(no_upgrade) > 5 else ''}"
        remediation = 'Enable auto minor version upgrades on RDS instances.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except Exception as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_s3_block_public(s3_client) -> Dict[str, Any]:
    CONTROL_ID = 'S3.1'
    REQUIRED_BLOCKS = ['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets']
    non_compliant = []
    buckets_checked = 0
    try:
        buckets_response = s3_client.list_buckets()
        buckets = buckets_response.get('Buckets', [])
        if not buckets: return create_standard_response(CONTROL_ID, 'PASS', 'No S3 buckets found.')
        futures = {}
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_bucket = {executor.submit(s3_client.get_public_access_block, Bucket=b['Name']): b['Name'] for b in buckets}
            for future in as_completed(future_to_bucket):
                bucket_name = future_to_bucket[future]
                buckets_checked += 1
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
                         buckets_checked -= 1 # Adjust count
                    elif e.response['Error']['Code'] == 'AccessDenied':
                         logger.warning(f"Access denied checking PublicAccessBlock for {bucket_name}")
                         non_compliant.append(f"{bucket_name} (Access Denied)")
                    else:
                         logger.error(f"Error getting public access block for {bucket_name}: {e}", exc_info=True)
                         non_compliant.append(f"{bucket_name} (Error)")
        status = 'PASS' if not non_compliant else 'FAIL'
        message = f"{buckets_checked - len(non_compliant)}/{buckets_checked} buckets checked have all public access blocks enabled."
        if non_compliant: message += f" Buckets lacking full block/error: {', '.join(non_compliant[:3])}{'...' if len(non_compliant) > 3 else ''}"
        remediation = 'Enable all four S3 Block Public Access settings for each listed bucket.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except ClientError as e: # Error listing buckets
        logger.error(f"Error listing buckets for {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to list S3 buckets: {str(e)}')
    except Exception as e:
        logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_s3_ssl(s3_client) -> Dict[str, Any]:
    CONTROL_ID = 'S3.5'
    SSL_POLICY_CONDITION = '"aws:SecureTransport": "false"'
    lacks_ssl_policy = []
    buckets_checked = 0
    try:
        buckets_response = s3_client.list_buckets()
        buckets = buckets_response.get('Buckets', [])
        if not buckets: return create_standard_response(CONTROL_ID, 'PASS', "No S3 buckets found.")
        futures = {}
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_bucket = {executor.submit(s3_client.get_bucket_policy, Bucket=b['Name']): b['Name'] for b in buckets}
            for future in as_completed(future_to_bucket):
                bucket_name = future_to_bucket[future]
                buckets_checked += 1
                policy_enforces_ssl = False
                try:
                    policy_str = future.result().get('Policy')
                    if policy_str and SSL_POLICY_CONDITION in policy_str:
                         policy_data = json.loads(policy_str)
                         for statement in policy_data.get('Statement', []):
                             if (statement.get('Effect') == 'Deny' and
                                 statement.get('Condition', {}).get('Bool', {}).get('aws:SecureTransport') == 'false'):
                                 policy_enforces_ssl = True; break
                    if not policy_enforces_ssl: lacks_ssl_policy.append(bucket_name)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchBucketPolicy': lacks_ssl_policy.append(bucket_name)
                    elif e.response['Error']['Code'] == 'NoSuchBucket': logger.warning(f"Bucket {bucket_name} vanished during S3.5 check."); buckets_checked -= 1
                    else: logger.error(f"Error getting policy for bucket {bucket_name}: {e}", exc_info=True); lacks_ssl_policy.append(f"{bucket_name} (Error)")
        status = 'PASS' if not lacks_ssl_policy else 'FAIL'
        message = f"{buckets_checked - len(lacks_ssl_policy)}/{buckets_checked} buckets checked enforce SSL via bucket policy."
        if lacks_ssl_policy: message += f" Buckets potentially lacking SSL enforcement: {', '.join(lacks_ssl_policy[:3])}{'...' if len(lacks_ssl_policy) > 3 else ''}"
        remediation = 'Add a bucket policy to deny requests not using SSL/TLS (aws:SecureTransport=false).' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except ClientError as e: # Error listing buckets
        logger.error(f"Error listing buckets for {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to list S3 buckets: {str(e)}')
    except Exception as e:
        logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_s3_public_access(s3_client) -> Dict[str, Any]:
    CONTROL_ID = 'S3.8'
    result = check_s3_block_public(s3_client) # Reuse S3.1 logic
    result['control'] = CONTROL_ID
    result['remediation'] = 'Ensure all settings under S3 Block Public Access are enabled.' if result['status'] == 'FAIL' else None
    return result

def check_s3_mfa_delete(s3_client) -> Dict[str, Any]:
    CONTROL_ID = 'S3.20'
    no_mfa_delete = []
    buckets_checked = 0
    try:
        buckets_response = s3_client.list_buckets()
        buckets = buckets_response.get('Buckets', [])
        if not buckets: return create_standard_response(CONTROL_ID, 'PASS', "No S3 buckets found.")
        futures = {}
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_bucket = {executor.submit(s3_client.get_bucket_versioning, Bucket=b['Name']): b['Name'] for b in buckets}
            for future in as_completed(future_to_bucket):
                bucket_name = future_to_bucket[future]
                buckets_checked += 1
                try:
                    versioning_info = future.result()
                    status = versioning_info.get('Status')
                    mfa_delete_status = versioning_info.get('MFADelete')
                    if status != 'Enabled' or mfa_delete_status != 'Enabled':
                         reason = "Versioning not Enabled" if status != 'Enabled' else "MFA Delete Disabled"
                         logger.debug(f"Bucket {bucket_name} fails S3.20 ({reason}).")
                         no_mfa_delete.append(bucket_name)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchBucket': logger.warning(f"Bucket {bucket_name} vanished during S3.20 check."); buckets_checked -= 1
                    else: logger.error(f"Error getting versioning/MFA Delete for bucket {bucket_name}: {e}", exc_info=True); no_mfa_delete.append(f"{bucket_name} (Error)")
        status = 'PASS' if not no_mfa_delete else 'FAIL'
        message = f"{buckets_checked - len(no_mfa_delete)}/{buckets_checked} buckets checked have Versioning and MFA Delete enabled."
        if no_mfa_delete: message += f" Buckets lacking MFA Delete (or Versioning/Error): {', '.join(no_mfa_delete[:3])}{'...' if len(no_mfa_delete) > 3 else ''}"
        remediation = 'Enable Versioning and MFA Delete on S3 buckets.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except ClientError as e: # Error listing buckets
        logger.error(f"Error listing buckets for {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to list S3 buckets: {str(e)}')
    except Exception as e:
        logger.error(f"Unexpected error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_s3_write_logging(cloudtrail_client) -> Dict[str, Any]:
    CONTROL_ID = 'S3.22'
    try:
        trails = paginate(cloudtrail_client, 'describe_trails', 'trailList')
        if not trails: return create_standard_response(CONTROL_ID, 'FAIL', "No CloudTrail trails found to check for S3 write logging.")
        trail_logs_s3_write = False
        for t in trails:
            trail_name = t.get('Name')
            if not trail_name: continue
            try:
                # Check event selectors
                selectors_resp = cloudtrail_client.get_event_selectors(TrailName=trail_name)
                selectors = selectors_resp.get('EventSelectors', [])
                has_write_selector = any(s.get('ReadWriteType') in ['WriteOnly', 'All'] for s in selectors)
                has_s3_data_event = any('DataResources' in s and any(ds.get('Type') == 'AWS::S3::Object' for ds in s['DataResources']) for s in selectors)
                # Check advanced event selectors
                adv_selectors = selectors_resp.get('AdvancedEventSelectors', [])
                has_adv_s3_write = False
                for adv_sel in adv_selectors:
                    is_s3 = any(f.get('Field') == 'eventSource' and 's3.amazonaws.com' in f.get('Equals', []) for f in adv_sel.get('FieldSelectors',[]))
                    is_write = any(f.get('Field') == 'readOnly' and 'false' in f.get('Equals', []) for f in adv_sel.get('FieldSelectors',[]))
                    if is_s3 and is_write: has_adv_s3_write = True; break
                if has_write_selector or has_s3_data_event or has_adv_s3_write:
                    trail_logs_s3_write = True; break # Found a trail logging S3 writes
            except ClientError as e: logger.warning(f"Failed to get event selectors for trail {trail_name}: {e}", exc_info=True)
        status = 'PASS' if trail_logs_s3_write else 'FAIL'
        message = "At least one CloudTrail trail logs S3 write events." if status == 'PASS' else "No CloudTrail trail found configured to log S3 write events."
        remediation = 'Configure CloudTrail event selectors to include S3 write data events.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except Exception as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')

def check_s3_read_logging(cloudtrail_client) -> Dict[str, Any]:
    CONTROL_ID = 'S3.23'
    try:
        trails = paginate(cloudtrail_client, 'describe_trails', 'trailList')
        if not trails: return create_standard_response(CONTROL_ID, 'FAIL', "No CloudTrail trails found to check for S3 read logging.")
        trail_logs_s3_read = False
        for t in trails:
            trail_name = t.get('Name')
            if not trail_name: continue
            try:
                selectors_resp = cloudtrail_client.get_event_selectors(TrailName=trail_name)
                selectors = selectors_resp.get('EventSelectors', [])
                has_read_selector = any(s.get('ReadWriteType') in ['ReadOnly', 'All'] for s in selectors)
                has_s3_data_event = any('DataResources' in s and any(ds.get('Type') == 'AWS::S3::Object' for ds in s['DataResources']) for s in selectors)
                adv_selectors = selectors_resp.get('AdvancedEventSelectors', [])
                has_adv_s3_read = False
                for adv_sel in adv_selectors:
                    is_s3 = any(f.get('Field') == 'eventSource' and 's3.amazonaws.com' in f.get('Equals', []) for f in adv_sel.get('FieldSelectors',[]))
                    is_read = any(f.get('Field') == 'readOnly' and 'true' in f.get('Equals', []) for f in adv_sel.get('FieldSelectors',[]))
                    if is_s3 and is_read: has_adv_s3_read = True; break
                if has_read_selector or has_s3_data_event or has_adv_s3_read:
                    trail_logs_s3_read = True; break
            except ClientError as e: logger.warning(f"Failed to get event selectors for trail {trail_name}: {e}", exc_info=True)
        status = 'PASS' if trail_logs_s3_read else 'FAIL'
        message = "At least one CloudTrail trail logs S3 read events." if status == 'PASS' else "No CloudTrail trail found configured to log S3 read events."
        remediation = 'Configure CloudTrail event selectors to include S3 read data events.' if status == 'FAIL' else None
        return create_standard_response(CONTROL_ID, status, message, remediation=remediation, remediation_available=(status == 'FAIL'))
    except Exception as e:
        logger.error(f"Error checking {CONTROL_ID}: {e}", exc_info=True)
        return create_standard_response(CONTROL_ID, 'ERROR', f'Failed to check: {str(e)}')


# --- Main Lambda Handler ---

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Main entry point for Lambda function.
    Handles the event processing for evaluation action.
    Returns results as JSON.
    """
    start_time = time.time() # Defined start_time
    logger.info(f"Received event: {json.dumps(event)}")

    # --- Instantiate Boto3 clients within handler ---
    try:
        iam_client = boto3.client('iam', config=retry_config)
        s3_client = boto3.client('s3', config=retry_config)
        ec2_client = boto3.client('ec2', config=retry_config)
        cloudtrail_client = boto3.client('cloudtrail', config=retry_config)
        rds_client = boto3.client('rds', config=retry_config)
        kms_client = boto3.client('kms', config=retry_config)
        efs_client = boto3.client('efs', config=retry_config)
        config_client = boto3.client('config', config=retry_config)
    except Exception as client_e:
        logger.error(f"Failed to initialize Boto3 clients: {client_e}", exc_info=True)
        return {'statusCode': 500, 'body': json.dumps({'error': 'Failed to initialize AWS clients'})}

    # Group clients for easier passing
    clients = {
        'iam': iam_client, 's3': s3_client, 'ec2': ec2_client,
        'cloudtrail': cloudtrail_client, 'rds': rds_client, 'kms': kms_client,
        'efs': efs_client, 'config': config_client,
    }

    # Mapping control ID to function and the client it needs
    # Defined here for clarity, could be loaded from elsewhere
    CONTROL_CHECK_MAP = {
        'Account.1': (check_security_contact, clients['iam']),
        'CloudTrail.1': (check_cloudtrail_enabled, clients['cloudtrail']),
        'CloudTrail.2': (check_cloudtrail_encryption, clients['cloudtrail']),
        'CloudTrail.4': (check_cloudtrail_validation, clients['cloudtrail']),
        'Config.1': (check_config_enabled, clients['config']),
        'EC2.2': (check_vpc_default_sg, clients['ec2']),
        'EC2.6': (check_vpc_flow_logs, clients['ec2']),
        'EC2.7': (check_ebs_encryption, clients['ec2']),
        'EC2.8': (check_imdsv2, clients['ec2']),
        'EC2.21': (check_nacl_open_ports, clients['ec2']),
        'EC2.53': (check_sg_open_ipv4, clients['ec2']),
        'EC2.54': (check_sg_open_ipv6, clients['ec2']),
        'EFS.1': (check_efs_encryption, clients['efs']),
        'IAM.2': (check_iam_user_policies, clients['iam']),
        'IAM.3': (check_iam_key_rotation, clients['iam']),
        'IAM.4': (check_root_access_keys, clients['iam']),
        'IAM.5': (check_iam_mfa_console, clients['iam']),
        'IAM.9': (check_root_mfa, clients['iam']),
        'IAM.15': (check_password_length, clients['iam']),
        'IAM.16': (check_password_reuse, clients['iam']),
        'IAM.18': (check_support_role, clients['iam']),
        'IAM.22': (check_unused_credentials, clients['iam']),
        'IAM.26': (check_expired_certificates, clients['iam']),
        'IAM.27': (check_cloudshell_policy, clients['iam']),
        'IAM.28': (check_access_analyzer, clients['iam']),
        'KMS.4': (check_kms_rotation, clients['kms']),
        'RDS.2': (check_rds_public, clients['rds']),
        'RDS.3': (check_rds_encryption, clients['rds']),
        'RDS.13': (check_rds_auto_upgrades, clients['rds']),
        'S3.1': (check_s3_block_public, clients['s3']),
        'S3.5': (check_s3_ssl, clients['s3']),
        'S3.8': (check_s3_public_access, clients['s3']), # Uses check_s3_block_public internally
        'S3.20': (check_s3_mfa_delete, clients['s3']),
        'S3.22': (check_s3_write_logging, clients['cloudtrail']),
        'S3.23': (check_s3_read_logging, clients['cloudtrail']),
    }

    action = event.get('action', 'evaluate')
    if action != 'evaluate':
        logger.error(f"Invalid action: {action}. Only 'evaluate' is supported in this version.")
        return {'statusCode': 400, 'body': json.dumps({'error': f'Invalid action: {action}. Only evaluate is supported.'})}

    results_dict = {}
    futures = {}
    logger.info(f"Starting compliance evaluation for {len(CONTROL_CHECK_MAP)} controls...")

    try:
        # Corrected ThreadPoolExecutor indentation: Both loops inside 'with'
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Submit checks
            for control_id, (check_function, client_instance) in CONTROL_CHECK_MAP.items():
                logger.debug(f"Submitting check for {control_id}")
                futures[executor.submit(check_function, client_instance)] = control_id

            # Collect results
            logger.info(f"Waiting for {len(futures)} checks to complete...")
            for future in as_completed(futures):
                control_id = futures[future]
                try:
                    result = future.result()
                    if result and isinstance(result, dict) and 'control' in result:
                         # Special handling for S3.8 reusing S3.1 logic
                         if control_id == 'S3.1':
                              results_dict[control_id] = result # Store S3.1 result
                              # Create and store S3.8 result
                              s3_8_result = result.copy()
                              s3_8_result['control'] = 'S3.8'
                              s3_8_result['remediation'] = 'Ensure all settings under S3 Block Public Access are enabled.' if result['status'] == 'FAIL' else None
                              results_dict['S3.8'] = s3_8_result
                         # Handle S3.8 submission explicitly (it calls check_s3_block_public)
                         elif control_id == 'S3.8':
                             results_dict[control_id] = result # Store the result returned by check_s3_public_access
                         # Standard case
                         else:
                              results_dict[control_id] = result
                         logger.debug(f"Completed check for {control_id}: {result.get('status')}")
                    else:
                         logger.error(f"Check function for {control_id} returned invalid/empty result: {result}")
                         results_dict[control_id] = create_standard_response(control_id, 'ERROR', 'Check function returned invalid/empty result.')
                except Exception as e:
                    logger.error(f"Exception executing check for {control_id}: {e}", exc_info=True)
                    results_dict[control_id] = create_standard_response(control_id, 'ERROR', f"Check execution failed: {e}")

        # --- Simplified JSON Return ---
        end_time = time.time()
        duration = end_time - start_time
        final_results_list = sorted(list(results_dict.values()), key=lambda x: x.get('control', ''))
        summary = {
            status: sum(1 for r in final_results_list if r.get('status') == status)
            for status in ['PASS', 'FAIL', 'ERROR']
        }
        report = {
            'version': 'Refactored-JSON', # Indicate version/format
            'timestamp_utc': datetime.now(timezone.utc).isoformat(),
            'duration_seconds': round(duration, 2),
            'summary': summary,
            'results': final_results_list
        }

        logger.info(f"Evaluation completed in {duration:.2f} seconds. Summary: {summary}")

        # Optional: Upload JSON report to S3
        if REPORT_BUCKET:
            report_key = f"report-json-{int(time.time())}.json"
            try:
                s3_client.put_object(
                    Bucket=REPORT_BUCKET,
                    Key=report_key,
                    Body=json.dumps(report, default=str, indent=2),
                    ContentType='application/json'
                )
                logger.info(f"Successfully uploaded JSON report to s3://{REPORT_BUCKET}/{report_key}")
            except ClientError as s3_e:
                logger.error(f"Failed to upload JSON report to S3 bucket {REPORT_BUCKET}: {s3_e}", exc_info=True)
            except Exception as s3_upload_e:
                logger.error(f"Unexpected error uploading JSON report: {s3_upload_e}", exc_info=True)

        return {
            'statusCode': 200,
            'body': json.dumps(report, default=str) # Ensure datetime is serializable
        }

    except Exception as e:
        logger.error(f"Unexpected error during handler execution: {e}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Handler execution failed: {str(e)}'})
        }

if __name__ == "__main__":
    # Example for local testing
    logger.info("Running local test evaluation...")
    test_event = {'action': 'evaluate'}
    lambda_response = lambda_handler(test_event, None)
    print("\n--- Lambda Response ---")
    print(json.dumps(lambda_response, indent=2))
    # Example of accessing body content if needed:
    # if lambda_response.get('statusCode') == 200:
    #     body_content = json.loads(lambda_response.get('body', '{}'))
    #     print("\n--- Report Summary ---")
    #     print(body_content.get('summary'))

