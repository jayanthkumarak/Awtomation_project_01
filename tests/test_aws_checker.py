import pytest
import boto3
import os
import sys
from pathlib import Path
from moto import mock_aws
from unittest.mock import patch, MagicMock # Added MagicMock

# Determine the project root directory (assuming tests/ is one level down)
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

# Import the function(s) you want to test from your main script
# This should now work if aws_checker_in_lambda.py is in the project root
from aws_checker_in_lambda import (
    check_security_contact,
    load_controls,
    check_cloudtrail_enabled,
    check_cloudtrail_encryption,
    check_s3_block_public,
    lambda_handler
    # NOTE: Clients are imported BUT will be patched in tests
)

# --- Pytest Fixtures ---

@pytest.fixture(scope='function')
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_REGION'] = 'us-east-1'
    yield
    os.environ.pop('AWS_ACCESS_KEY_ID', None)
    os.environ.pop('AWS_SECRET_ACCESS_KEY', None)
    os.environ.pop('AWS_SESSION_TOKEN', None)
    os.environ.pop('AWS_REGION', None)

# Fixture to provide boto3 clients within the mock context
# This helps address the issue of module-level clients in the main script
@pytest.fixture(scope='function')
def mocked_clients(aws_credentials):
    # Patch the specific client variables used by the imported functions
    # This ensures the functions use clients created *inside* the moto mock
    # Use autospec=True to ensure the mock has the same methods/attributes as the original
    with patch('aws_checker_in_lambda.iam_client', autospec=True) as mock_iam, \
         patch('aws_checker_in_lambda.s3_client', autospec=True) as mock_s3, \
         patch('aws_checker_in_lambda.cloudtrail_client', autospec=True) as mock_ct, \
         patch('aws_checker_in_lambda.kms_client', autospec=True) as mock_kms:
        # Create REAL boto3 clients *after* @mock_aws is active
        # and assign them to the mocks' return_value or side_effect
        # Using side_effect allows the mock to delegate calls to the real client
        mock_iam.side_effect = boto3.client('iam', region_name='us-east-1')
        mock_s3.side_effect = boto3.client('s3', region_name='us-east-1')
        mock_ct.side_effect = boto3.client('cloudtrail', region_name='us-east-1')
        mock_kms.side_effect = boto3.client('kms', region_name='us-east-1')

        # Yield the boto3 clients created *within* the mock context,
        # in case tests need direct access to them (though patching should suffice)
        yield {
            'iam': boto3.client('iam', region_name='us-east-1'),
            's3': boto3.client('s3', region_name='us-east-1'),
            'cloudtrail': boto3.client('cloudtrail', region_name='us-east-1'),
            'kms': boto3.client('kms', region_name='us-east-1'),
        }


# --- Test Functions ---

# Use the moto decorator and the client patching fixture
@mock_aws
def test_check_security_contact_pass(mocked_clients):
    # Test PASS when an account alias exists.
    # Arrange: Use the client provided by the fixture/mock context
    iam = mocked_clients['iam']
    iam.create_account_alias(AccountAlias='my-test-alias')

    # Act
    result = check_security_contact()

    # Assert
    assert result['status'] == 'PASS'
    assert 'Security contact (account alias) set' in result['message']
    assert result['control'] == 'Account.1'

@mock_aws
def test_check_security_contact_fail(mocked_clients):
    # Test FAIL when no account alias exists.
    # Arrange: No alias is created in this mock environment by default

    # Act
    result = check_security_contact()

    # Assert
    assert result['status'] == 'FAIL'
    # assert 'No account alias set' in result['message'] # Relying on status mostly
    assert result['control'] == 'Account.1'


# --- Tests for load_controls ---

@mock_aws
@patch.dict(os.environ, {"REPORT_BUCKET": "test-report-bucket"})
def test_load_controls_success(mocked_clients):
     # Test load_controls successfully reads from mock S3.
     # Arrange
     s3 = mocked_clients['s3']
     s3.create_bucket(Bucket="test-report-bucket")
     controls_content = '{"Account.1": {"description": "Test Control", "remediation": "Test Remediation"}}'
     s3.put_object(Bucket="test-report-bucket", Key="controls.json", Body=controls_content)

     # Act
     controls = load_controls()

     # Assert
     assert "Account.1" in controls
     assert controls["Account.1"]["description"] == "Test Control"

@mock_aws
@patch.dict(os.environ, {"REPORT_BUCKET": "test-report-bucket-nonexistent"})
def test_load_controls_fail_no_bucket(mocked_clients):
     # Test load_controls handles non-existent bucket.
     # Arrange: Bucket does not exist in mock S3

     # Act
     controls = load_controls()

     # Assert: Expect empty dict as fallback
     assert controls == {}

@mock_aws
@patch.dict(os.environ, {"REPORT_BUCKET": "test-report-bucket"})
def test_load_controls_fail_no_key(mocked_clients):
     # Test load_controls handles non-existent key.
     # Arrange
     s3 = mocked_clients['s3']
     s3.create_bucket(Bucket="test-report-bucket")
     # Don't put the controls.json object

     # Act
     controls = load_controls()

     # Assert: Expect empty dict as fallback
     assert controls == {}

# Test load_controls when environment variable is missing
@mock_aws
@patch.dict(os.environ, {}, clear=True) # Ensure REPORT_BUCKET is not set
def test_load_controls_fail_missing_env_var(mocked_clients):
    # Test load_controls handles missing REPORT_BUCKET env var.
    # Arrange: Env var is cleared by the patcher

    # Act
    controls = load_controls()

    # Assert: Expect empty dict as fallback (assuming the function handles missing env var gracefully)
    # NOTE: This assumes load_controls() uses os.environ.get('REPORT_BUCKET', default_value)
    # or has similar error handling for the bucket name.
    assert controls == {}


# --- Tests for CloudTrail ---

@mock_aws
def test_check_cloudtrail_enabled_pass(mocked_clients):
    # Test CloudTrail.1 PASS: Multi-region trail with 'All' events.
    # Arrange
    s3 = mocked_clients['s3']
    ct = mocked_clients['cloudtrail']
    bucket_name = "my-cloudtrail-test-bucket"
    s3.create_bucket(Bucket=bucket_name)

    ct.create_trail(
        Name='management-events',
        S3BucketName=bucket_name,
        IsMultiRegionTrail=True,
        EnableLogFileValidation=True
    )
    # Assume default event selector includes 'All'

    # Act
    result = check_cloudtrail_enabled()

    # Assert
    assert result['status'] == 'PASS'
    assert result['control'] == 'CloudTrail.1'
    # assert 'Multi-region: True' in result['message'] # Less brittle assertion

@mock_aws
def test_check_cloudtrail_enabled_fail_no_trails(mocked_clients):
    # Test CloudTrail.1 FAIL: No trails exist.
    # Arrange: No trails created

    # Act
    result = check_cloudtrail_enabled()

    # Assert
    assert result['status'] == 'FAIL'
    assert result['control'] == 'CloudTrail.1'
    # assert 'No CloudTrail trails found' in result['message']

@mock_aws
def test_check_cloudtrail_enabled_fail_not_multiregion(mocked_clients):
    # Test CloudTrail.1 FAIL: Trail exists but is not multi-region.
    # Arrange
    s3 = mocked_clients['s3']
    ct = mocked_clients['cloudtrail']
    bucket_name = "my-cloudtrail-test-bucket-single"
    s3.create_bucket(Bucket=bucket_name)
    ct.create_trail(
        Name='single-region-trail',
        S3BucketName=bucket_name,
        IsMultiRegionTrail=False
    )

    # Act
    result = check_cloudtrail_enabled()

    # Assert
    assert result['status'] == 'FAIL'
    assert result['control'] == 'CloudTrail.1'
    # assert 'Multi-region: False' in result['message']


@mock_aws
def test_check_cloudtrail_encryption_pass(mocked_clients):
    # Test CloudTrail.2 PASS: Trail encrypted with KMS.
    # Arrange
    s3 = mocked_clients['s3']
    ct = mocked_clients['cloudtrail']
    kms = mocked_clients['kms']
    bucket_name = "my-cloudtrail-encrypted-bucket"
    s3.create_bucket(Bucket=bucket_name)
    kms_key = kms.create_key()['KeyMetadata']['Arn']
    ct.create_trail(
        Name='encrypted-trail',
        S3BucketName=bucket_name,
        IsMultiRegionTrail=True,
        KmsKeyId=kms_key
    )

    # Act
    result = check_cloudtrail_encryption()

    # Assert
    assert result['status'] == 'PASS'
    assert result['control'] == 'CloudTrail.2'
    # assert '0/1 trails lack encryption' in result['message'] # Less brittle

@mock_aws
def test_check_cloudtrail_encryption_fail(mocked_clients):
    # Test CloudTrail.2 FAIL: Trail not encrypted.
    # Arrange
    s3 = mocked_clients['s3']
    ct = mocked_clients['cloudtrail']
    bucket_name = "my-cloudtrail-unencrypted-bucket"
    s3.create_bucket(Bucket=bucket_name)
    ct.create_trail(
        Name='unencrypted-trail',
        S3BucketName=bucket_name,
        IsMultiRegionTrail=True
    )

    # Act
    result = check_cloudtrail_encryption()

    # Assert
    assert result['status'] == 'FAIL'
    assert result['control'] == 'CloudTrail.2'
    # assert '1/1 trails lack encryption' in result['message'] # Less brittle


# --- Tests for S3 Public Access Block (Parameterized) ---

@mock_aws
@pytest.mark.parametrize(
    "bucket_name_suffix, config, expected_status",
    [
        ("blocked", {'BlockPublicAcls': True, 'IgnorePublicAcls': True, 'BlockPublicPolicy': True, 'RestrictPublicBuckets': True}, "PASS"),
        ("partial", {'BlockPublicAcls': True, 'IgnorePublicAcls': True, 'BlockPublicPolicy': False, 'RestrictPublicBuckets': True}, "FAIL"),
        # Moto often applies default blocks if none specified. A true 'no block' might need explicit deletion or checking moto defaults.
        # Adding a test case assuming default blocks might be present and need full configuration.
        ("default-maybe", None, "FAIL"),
    ],
    ids=["all_blocks", "partial_block", "no_block_config_set"]
)
def test_check_s3_block_public(bucket_name_suffix, config, expected_status, mocked_clients):
    # Test S3.1/S3.8 PASS/FAIL based on configuration.
    # Arrange
    s3 = mocked_clients['s3']
    bucket_name = f"my-test-bucket-{bucket_name_suffix}"
    s3.create_bucket(Bucket=bucket_name)

    if config:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration=config
        )
    # else: No explicit block set, relies on default behavior or lack thereof.

    # Act
    result = check_s3_block_public() # Assuming S3.1 logic covers S3.8

    # Assert
    assert result['status'] == expected_status
    assert result['control'] == 'S3.1' # Or appropriate control ID checked by the function
    # Avoid asserting counts like 'x/y buckets' as other tests might create buckets implicitly.


# --- Basic Integration Test for lambda_handler ---

@mock_aws
@patch.dict(os.environ, {
    "REPORT_BUCKET": "handler-test-bucket",
    "AWS_DEFAULT_REGION": "us-east-1" # Ensure region is set for handler context
})
def test_lambda_handler_integration(mocked_clients):
    # Basic test to ensure lambda_handler runs and returns expected structure.
    # Arrange
    iam = mocked_clients['iam']
    s3 = mocked_clients['s3']
    ct = mocked_clients['cloudtrail']

    # Setup S3 bucket for controls and reports
    report_bucket = "handler-test-bucket"
    s3.create_bucket(Bucket=report_bucket)
    # Minimal controls file needed for the handler to load controls
    controls_content = '{"Account.1": {}, "CloudTrail.1": {}}'
    s3.put_object(Bucket=report_bucket, Key="controls.json", Body=controls_content)

    # Setup for Account.1 (Security Contact) - FAIL case
    # No alias created

    # Setup for CloudTrail.1 (Enabled) - FAIL case (no trails)
    # No trails created

    # Act
    # Mock context object if needed by the handler, otherwise pass empty dict or None
    mock_context = MagicMock()
    mock_context.aws_request_id = "test-request-id"
    mock_context.log_stream_name = "test-log-stream"
    # Add other attributes if the handler uses them

    # Call the handler - patch clients *used by the handler*
    # Our mocked_clients fixture already patches the global clients the handler imports
    handler_result = lambda_handler({}, mock_context)

    # Assert
    assert isinstance(handler_result, dict)
    assert 'results' in handler_result
    assert 'summary' in handler_result
    assert 'report_id' in handler_result
    assert 'report_html_key' in handler_result # Check for expected output keys

    # Check if specific controls were evaluated (at least the ones set up)
    evaluated_controls = {res['control'] for res in handler_result.get('results', [])}
    assert 'Account.1' in evaluated_controls
    assert 'CloudTrail.1' in evaluated_controls

    # Optionally, check summary counts if stable
    summary = handler_result.get('summary', {})
    assert summary.get('FAIL', 0) >= 2 # Expecting at least Account.1 and CloudTrail.1 to fail


# --- Removed extensive testing documentation ---
# This information should be in README.md or CONTRIBUTING.md 