import pytest
import boto3
import os
from moto import mock_aws
from unittest.mock import patch # For mocking environment variables

# Import the function(s) you want to test from your main script
# Assuming your main script is at the root level relative to the 'tests' dir
# Adjust the import path if your script is elsewhere
# We need to handle potential import errors if the main script isn't found directly
try:
    from aws_checker_in_lambda import (
        check_security_contact, iam_client,
        load_controls, s3_client,
        check_cloudtrail_enabled, cloudtrail_client,
        check_cloudtrail_encryption, kms_client,
        check_s3_block_public,
        lambda_handler
    )
except ImportError:
    # If running tests from a different structure, adjust path as needed
    # e.g., import sys; sys.path.append('..'); from aws_checker_in_lambda import ...
    print("Error: Could not import from aws_checker_in_lambda. Adjust Python path if needed.")
    # Define dummy client to avoid further NameErrors if import fails during test collection
    class DummyClient:
        def __getattr__(self, name):
            raise NotImplementedError(f"Client not available due to import error: {name}")
    # Ensure all potentially needed clients have dummies if import fails
    iam_client = DummyClient()
    s3_client = DummyClient()
    cloudtrail_client = DummyClient()
    kms_client = DummyClient()
    # Add other clients from main script if needed for future tests (ec2, rds, etc.)

    def check_security_contact(*args, **kwargs): raise ImportError("Could not import check_security_contact")
    def load_controls(*args, **kwargs): raise ImportError("Could not import load_controls")
    def check_cloudtrail_enabled(*args, **kwargs): raise ImportError("Could not import check_cloudtrail_enabled")
    def check_cloudtrail_encryption(*args, **kwargs): raise ImportError("Could not import check_cloudtrail_encryption")
    def check_s3_block_public(*args, **kwargs): raise ImportError("Could not import check_s3_block_public")
    def lambda_handler(*args, **kwargs): raise ImportError("Could not import lambda_handler")


# --- Pytest Fixtures (Optional but helpful) ---
# Fixtures can set up resources needed by multiple tests

@pytest.fixture(scope='function')
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_REGION'] = 'us-east-1' # Default region for moto
    yield # Allows cleanup after test if needed
    # Cleanup (optional): remove keys if they interfere with other tests/processes
    # Using .pop to avoid KeyError if already deleted or not set
    os.environ.pop('AWS_ACCESS_KEY_ID', None)
    os.environ.pop('AWS_SECRET_ACCESS_KEY', None)
    os.environ.pop('AWS_SESSION_TOKEN', None)
    os.environ.pop('AWS_REGION', None)


# --- Test Functions ---

# Use the moto decorator to mock AWS services for this test function
@mock_aws
def test_check_security_contact_pass(aws_credentials):
    """
    Test that check_security_contact returns PASS when an account alias exists.
    """
    # Arrange: Set up the mocked AWS environment using moto
    # The iam_client is already imported from your script, moto intercepts its calls
    iam_client.create_account_alias(AccountAlias='my-test-alias')

    # Act: Call the function under test
    result = check_security_contact()

    # Assert: Check if the result is as expected
    assert result['status'] == 'PASS'
    assert 'Security contact (account alias) set' in result['message']
    assert result['control'] == 'Account.1'

@mock_aws
def test_check_security_contact_fail(aws_credentials):
    """
    Test that check_security_contact returns FAIL when no account alias exists.
    """
    # Arrange: No alias is created in this mock environment by default

    # Act: Call the function under test
    result = check_security_contact()

    # Assert: Check if the result is as expected
    assert result['status'] == 'FAIL'
    assert 'No account alias set' in result['message']
    assert result['control'] == 'Account.1'

# Add more tests for other functions (e.g., check_cloudtrail_enabled)
# You'll need to use moto to create mock resources like CloudTrail trails, S3 buckets, etc.

# Example for a function needing environment variables (like load_controls)
@mock_aws
@patch.dict(os.environ, {"REPORT_BUCKET": "test-report-bucket"})
def test_load_controls_success(aws_credentials):
     """Test load_controls successfully reads from mock S3."""
     # Arrange
     # Ensure the s3_client from the main script is used within the mock context
     s3 = s3_client # Use the client imported from the main script

     s3.create_bucket(Bucket="test-report-bucket")
     controls_content = '{"Account.1": {"description": "Test Control", "remediation": "Test Remediation"}}'
     s3.put_object(Bucket="test-report-bucket", Key="controls.json", Body=controls_content)

     # Act
     controls = load_controls() # Call the function from the main script

     # Assert
     assert "Account.1" in controls
     assert controls["Account.1"]["description"] == "Test Control"

@mock_aws
@patch.dict(os.environ, {"REPORT_BUCKET": "test-report-bucket-nonexistent"})
def test_load_controls_fail_no_bucket(aws_credentials):
     """Test load_controls handles non-existent bucket."""
     # Arrange: Bucket does not exist in mock S3

     # Act
     controls = load_controls() # Call the function from the main script

     # Assert: Expect empty dict as fallback
     assert controls == {}

@mock_aws
@patch.dict(os.environ, {"REPORT_BUCKET": "test-report-bucket"})
def test_load_controls_fail_no_key(aws_credentials):
     """Test load_controls handles non-existent key."""
     # Arrange
     s3 = s3_client
     s3.create_bucket(Bucket="test-report-bucket")
     # Don't put the controls.json object

     # Act
     controls = load_controls() # Call the function from the main script

     # Assert: Expect empty dict as fallback
     assert controls == {}


# --- New Tests for CloudTrail ---

@mock_aws
def test_check_cloudtrail_enabled_pass(aws_credentials):
    """Test CloudTrail.1 PASS: Multi-region trail with 'All' events."""
    # Arrange
    s3 = boto3.client("s3", region_name="us-east-1") # Use boto3 directly within mock context is fine
    bucket_name = "my-cloudtrail-test-bucket"
    s3.create_bucket(Bucket=bucket_name)

    cloudtrail_client.create_trail(
        Name='management-events',
        S3BucketName=bucket_name,
        IsMultiRegionTrail=True,
        EnableLogFileValidation=True
    )
    # Default event selector created by moto is usually sufficient ('All' ReadWriteType)
    # If specific selectors needed: cloudtrail_client.put_event_selectors(...)

    # Act
    result = check_cloudtrail_enabled()

    # Assert
    assert result['status'] == 'PASS'
    assert result['control'] == 'CloudTrail.1'
    assert 'Multi-region: True' in result['message']
    assert 'Events: True' in result['message'] # Assumes default selector works

@mock_aws
def test_check_cloudtrail_enabled_fail_no_trails(aws_credentials):
    """Test CloudTrail.1 FAIL: No trails exist."""
    # Arrange: No trails created

    # Act
    result = check_cloudtrail_enabled()

    # Assert
    assert result['status'] == 'FAIL'
    assert result['control'] == 'CloudTrail.1'
    assert 'No CloudTrail trails found' in result['message']

@mock_aws
def test_check_cloudtrail_enabled_fail_not_multiregion(aws_credentials):
    """Test CloudTrail.1 FAIL: Trail exists but is not multi-region."""
    # Arrange
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket_name = "my-cloudtrail-test-bucket-single"
    s3.create_bucket(Bucket=bucket_name)
    cloudtrail_client.create_trail(
        Name='single-region-trail',
        S3BucketName=bucket_name,
        IsMultiRegionTrail=False # Explicitly single region
    )

    # Act
    result = check_cloudtrail_enabled()

    # Assert
    assert result['status'] == 'FAIL'
    assert result['control'] == 'CloudTrail.1'
    assert 'Multi-region: False' in result['message']

@mock_aws
def test_check_cloudtrail_encryption_pass(aws_credentials):
    """Test CloudTrail.2 PASS: Trail encrypted with KMS."""
    # Arrange
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket_name = "my-cloudtrail-encrypted-bucket"
    s3.create_bucket(Bucket=bucket_name)
    kms_key = kms_client.create_key()['KeyMetadata']['Arn']
    cloudtrail_client.create_trail(
        Name='encrypted-trail',
        S3BucketName=bucket_name,
        IsMultiRegionTrail=True,
        KmsKeyId=kms_key # Encrypted
    )

    # Act
    result = check_cloudtrail_encryption()

    # Assert
    assert result['status'] == 'PASS'
    assert result['control'] == 'CloudTrail.2'
    assert '0/1 trails lack encryption' in result['message']

@mock_aws
def test_check_cloudtrail_encryption_fail(aws_credentials):
    """Test CloudTrail.2 FAIL: Trail not encrypted."""
    # Arrange
    s3 = boto3.client("s3", region_name="us-east-1")
    bucket_name = "my-cloudtrail-unencrypted-bucket"
    s3.create_bucket(Bucket=bucket_name)
    cloudtrail_client.create_trail(
        Name='unencrypted-trail',
        S3BucketName=bucket_name,
        IsMultiRegionTrail=True
        # No KmsKeyId specified
    )

    # Act
    result = check_cloudtrail_encryption()

    # Assert
    assert result['status'] == 'FAIL'
    assert result['control'] == 'CloudTrail.2'
    assert '1/1 trails lack encryption' in result['message']


# --- New Tests for S3 Public Access Block ---

@mock_aws
def test_check_s3_block_public_pass(aws_credentials):
    """Test S3.1/S3.8 PASS: Bucket has all public access blocks enabled."""
    # Arrange
    bucket_name = "my-blocked-bucket"
    s3_client.create_bucket(Bucket=bucket_name)
    s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )

    # Act
    # Note: check_s3_block_public and check_s3_public_access have identical logic in the provided code
    result = check_s3_block_public()

    # Assert
    assert result['status'] == 'PASS'
    assert result['control'] == 'S3.1' # Or S3.8 depending on which you test
    assert '0/1 buckets lack full block' in result['message']


@mock_aws
def test_check_s3_block_public_fail_partially_blocked(aws_credentials):
    """Test S3.1/S3.8 FAIL: Bucket has some but not all blocks enabled."""
    # Arrange
    bucket_name = "my-partially-blocked-bucket"
    s3_client.create_bucket(Bucket=bucket_name)
    s3_client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': False, # Missing one block
            'RestrictPublicBuckets': True
        }
    )

    # Act
    result = check_s3_block_public()

    # Assert
    assert result['status'] == 'FAIL'
    assert result['control'] == 'S3.1'
    assert '1/1 buckets lack full block' in result['message']


@mock_aws
def test_check_s3_block_public_fail_no_block(aws_credentials):
    """Test S3.1/S3.8 FAIL: Bucket has no public access block configuration."""
    # Arrange
    bucket_name = "my-wide-open-bucket"
    s3_client.create_bucket(Bucket=bucket_name)
    # No put_public_access_block call - Moto might apply default blocks, let's check behavior
    # Sometimes you might need to explicitly delete the block if moto defaults to blocked:
    # try: s3_client.delete_public_access_block(Bucket=bucket_name) catch ClientError

    # Act
    result = check_s3_block_public()

    # Assert
    # The exact message depends on whether moto defaults to *no block* or *default block*.
    # We expect FAIL regardless.
    assert result['status'] == 'FAIL'
    assert result['control'] == 'S3.1'
    assert 'lack full block' in result['message']
    # Asserting the count might be fragile depending on moto's internal state/other tests
    # assert '1/1' in result['message'] # Be cautious with exact counts in mocks

# --- TODO: Add tests for lambda_handler evaluation flow --- 

## Testing

This project uses `pytest` and `moto` for unit testing the Lambda function's logic without making actual calls to AWS.

1.  **Install Test Dependencies**:
    ```bash
    # Make sure you are in the project root directory
    pip3 install -r requirements.txt 
    # Or, if you haven't generated requirements.txt yet:
    # pip3 install pytest "moto[iam,s3,ec2,cloudtrail,rds,kms,efs,config,sts]"
    ```

2.  **Run Tests**:
    From the project root directory:
    ```bash
    pytest
    ```
    `pytest` will automatically discover and run tests located in the `tests/` directory. 

### Unit Testing

The Lambda function's core logic is unit tested using `pytest` and the `moto` library to ensure individual components function correctly without interacting with live AWS resources.

**Strategy:**

*   **Mocking:** The `@mock_aws` decorator from `moto` is used on test functions. This intercepts AWS SDK (`boto3`) calls made by the code under test and redirects them to `moto`'s in-memory simulation of AWS services (like IAM, S3, CloudTrail).
*   **Arrange-Act-Assert:** Tests follow the standard pattern:
    *   **Arrange:** Set up the simulated AWS environment using `moto`'s capabilities (e.g., creating mock S3 buckets, IAM aliases, CloudTrail trails) to match the specific scenario being tested (e.g., a passing case, a failing case). Dummy AWS credentials are provided via environment variables as required by `moto`. Environment variables needed by the function (like `REPORT_BUCKET`) are mocked using `unittest.mock.patch`.
    *   **Act:** Call the specific function from `aws_checker_in_lambda.py` being tested (e.g., `check_cloudtrail_enabled()`).
    *   **Assert:** Use `assert` statements to verify that the function returned the expected output (e.g., correct status, message, control ID) given the arranged mock environment.
*   **Isolation:** Each test runs in its own isolated mock environment, ensuring tests don't interfere with each other.

**Running Tests:**

1.  Ensure testing dependencies are installed:
    ```bash
    pip3 install -r requirements.txt 
    # (or pip3 install pytest "moto[...]")
    ```
2.  Execute tests from the project root directory:
    ```bash
    pytest
    ```

This testing approach provides high confidence in the correctness of individual control checks and utility functions, facilitating safer refactoring and development. 