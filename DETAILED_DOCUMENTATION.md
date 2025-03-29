# AWS Compliance Checker - Detailed Technical Documentation

## Project Overview

This project provides a comprehensive AWS compliance checking solution with two main components:

1. **AWS Compliance Checker Lambda** - A Python-based AWS Lambda function that evaluates AWS resources against CIS AWS Foundations Benchmark v3.0 security best practices.
2. **Compliance Dashboard** - A React-based web interface that displays compliance results, allowing users to visualize and manage compliance issues.

This documentation provides in-depth technical details about the architecture, components, and implementation of both parts of the system.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [AWS Compliance Checker Lambda](#aws-compliance-checker-lambda)
  - [Main Components](#main-components)
  - [Control Functions](#control-functions)
  - [Remediation Functions](#remediation-functions)
  - [Utility Functions](#utility-functions)
  - [AWS Services Evaluated](#aws-services-evaluated)
- [Compliance Dashboard](#compliance-dashboard)
  - [Frontend Architecture](#frontend-architecture)
  - [Key Components](#key-components)
  - [State Management](#state-management)
  - [API Integration](#api-integration)
- [Deployment and Configuration](#deployment-and-configuration)
- [Security Considerations](#security-considerations)
- [Future Enhancements](#future-enhancements)

---

## Architecture Overview

The system uses a serverless architecture where:

1. The Lambda function performs regular scans of the AWS environment
2. Results are stored in an S3 bucket
3. The compliance dashboard retrieves and displays these results
4. Optional remediation actions can be triggered through the dashboard

![Architecture Diagram (placeholder)]()

---

## AWS Compliance Checker Lambda

The Lambda function is the core of the compliance checking system, evaluating AWS resources against security best practices defined in the CIS AWS Foundations Benchmark v3.0.

### Main Components

The Lambda function is defined in `aws_checker_in_lambda.py` and consists of:

- A main `lambda_handler` function that processes incoming events
- Control check functions (`check_*`) that evaluate specific security controls
- Remediation functions (`remediate_*`) that can fix certain security issues
- Data fetching functions (`fetch_*`) and a centralized cache (`invocation_cache`) to retrieve AWS resource data efficiently.
- Utility functions for reporting and resource management
- Parallel execution using `concurrent.futures.ThreadPoolExecutor` for checks and data fetching to improve performance.
- Mappings (`FETCH_MAP`, `CONTROL_CHECK_MAP`) to dynamically manage data fetching and control execution.

#### Lambda Handler

```python
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
```

The Lambda handler can be triggered by:
- CloudWatch Events for scheduled scans
- API Gateway for on-demand scans
- Direct invocation for testing

It orchestrates the compliance checking process by calling individual control functions and aggregating the results.

### Control Functions

The Lambda includes over 30 control check functions that each evaluate a specific security control. Each function follows a consistent pattern:

1. Query the relevant AWS service(s)
2. Evaluate the configuration against best practices
3. Return a standardized result dictionary

Example control check function:

```python
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
```

### Control Checks Implemented

The system implements over 30 security control checks, including:

| Control ID | Name | Description | Severity |
|------------|------|-------------|----------|
| Account.1 | Security Contact Info | Ensure security contact information is registered | Medium |
| CloudTrail.1 | CloudTrail Enabled | Ensure CloudTrail is enabled in all regions | Critical |
| CloudTrail.2 | CloudTrail Encryption | Ensure CloudTrail logs are encrypted | High |
| EC2.8 | IMDSv2 Enabled | Ensure EC2 instances use IMDSv2 | High |
| IAM.4 | No Root Access Keys | Ensure no root account access key exists | Critical |
| RDS.2 | RDS No Public Access | Ensure RDS instances are not publicly accessible | Critical |
| S3.1 | S3 Block Public Access | Ensure S3 buckets block public access | Critical |

Each control check follows a consistent pattern but contains logic specific to its AWS service.

### Remediation Functions

For some security issues, the system provides automated remediation capabilities:

```python
def remediate_cloudtrail_encryption(dry_run: bool = True, confirm: bool = False, **kwargs) -> Dict[str, str]:
    """
    Remediate CloudTrail encryption by enabling KMS encryption for trails.
    
    Args:
        dry_run: If True, only simulate the remediation
        confirm: If True, apply remediation without additional confirmation
        
    Returns:
        Dict with remediation status information
    """
    # Implementation details...
```

The remediation functions follow security best practices by:
1. First backing up the current configuration
2. Applying only the minimum changes needed to achieve compliance
3. Providing detailed logs of changes made

### Utility Functions

Several utility functions support the main functionality:

```python
def load_controls() -> Dict[str, Any]:
    """Load control definitions from controls.json file."""
    
def generate_presigned_url(bucket: str, key: str, expiry: int = 3600) -> str:
    """Generate a presigned URL for S3 object access."""
    
def generate_html_report(results: Dict[str, Any]) -> str:
    """Generate an HTML report from compliance results."""
```

### AWS Services Evaluated

The Lambda function evaluates compliance across multiple AWS services:

- **IAM**: Password policies, access keys, MFA, user policies
- **CloudTrail**: Logging configuration, encryption, validation
- **S3**: Public access settings, encryption, logging
- **EC2/VPC**: Security groups, NACLs, flow logs, IMDSv2
- **RDS**: Public accessibility, encryption, automatic upgrades
- **KMS**: Key rotation policies
- **EFS**: Encryption settings
- **Config**: Service enablement

### Unit Testing

The Lambda function's core logic is unit tested using `pytest` and the `moto` library to ensure individual components function correctly without interacting with live AWS resources.

**Strategy:**

-   **Mocking:** The `@mock_aws` decorator from `moto` is used on test functions. This intercepts AWS SDK (`boto3`) calls made by the code under test and redirects them to `moto`'s in-memory simulation of AWS services (like IAM, S3, CloudTrail).
-   **Arrange-Act-Assert:** Tests follow the standard pattern:
    -   **Arrange:** Set up the simulated AWS environment using `moto`'s capabilities (e.g., creating mock S3 buckets, IAM aliases, CloudTrail trails) to match the specific scenario being tested (e.g., a passing case, a failing case). Dummy AWS credentials are provided via environment variables as required by `moto`. Environment variables needed by the function (like `REPORT_BUCKET`) are mocked using `unittest.mock.patch`.
    -   **Act:** Call the specific function from `aws_checker_in_lambda.py` being tested (e.g., `check_cloudtrail_enabled()`).
    -   **Assert:** Use `assert` statements to verify that the function returned the expected output (e.g., correct status, message, control ID) given the arranged mock environment.
-   **Isolation:** Each test runs in its own isolated mock environment, ensuring tests don't interfere with each other.

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

---

## Compliance Dashboard

The compliance dashboard provides a user-friendly interface for viewing and managing compliance results.

### Frontend Architecture

The dashboard is built using:
- React for UI components
- Redux for state management
- React Router for navigation
- Axios for API requests
- Material-UI for styling

### Key Components

The dashboard consists of several key components:

#### Layout Components

- **Header**: Contains navigation, user profile, and global actions
- **Sidebar**: Provides navigation and displays compliance score
- **Footer**: Contains copyright and additional links

#### Page Components

- **DashboardPage**: Main dashboard displaying compliance overview
- **ControlsPage**: List of all controls with filtering and sorting
- **ControlDetailPage**: Detailed view of a specific control
- **HistoryPage**: View historical compliance scan results
- **NotFoundPage**: 404 error page

#### Functional Components

- **ComplianceScore**: Visual representation of overall compliance score
- **ControlsList**: Filterable, sortable list of controls
- **RemediationAction**: UI for triggering remediation actions
- **ScanHistory**: Timeline of compliance scans

### State Management

The dashboard uses Redux for state management with the following key slices:

- **authSlice**: Manages authentication state
- **controlsSlice**: Manages controls data and filtering
- **scanSlice**: Manages scan data and operations
- **uiSlice**: Manages UI state (loading, errors, notifications)

### API Integration

The dashboard communicates with backend APIs via:

- REST endpoints for retrieving compliance data
- WebSockets for real-time updates during scans
- Authentication APIs for user management

Key API routes include:

- `/api/controls` - Get all controls
- `/api/scans` - Get scan history
- `/api/remediate/{controlId}` - Trigger remediation

---

## Deployment and Configuration

### Lambda Deployment

The AWS Lambda function is deployed using AWS SAM (Serverless Application Model). The `sam.yaml` file defines:

- Lambda function resources and permissions
- S3 buckets for reports and backups
- CloudWatch alarms and dashboards
- API Gateway endpoints

Key SAM template parameters:

- `ReportBucket`: S3 bucket for compliance reports
- `BackupBucket`: S3 bucket for configuration backups
- `LogLevel`: Logging verbosity
- `LambdaTimeout`: Maximum execution time for the Lambda
- `LambdaMemory`: Memory allocation for the Lambda

### Dashboard Deployment

The dashboard can be deployed as:
1. A static website hosted in S3
2. A containerized application in AWS ECS
3. A serverless application using AWS Amplify

---

## Security Considerations

The compliance checker is designed with security in mind:

1. **Principle of Least Privilege**: The Lambda function uses IAM permissions tailored to the specific API calls needed
2. **Data Protection**: All reports and backups are stored in encrypted S3 buckets
3. **Log Monitoring**: Failed checks and errors are logged to CloudWatch
4. **Access Control**: The dashboard uses authentication and authorization to restrict access

---

## Future Enhancements

Planned future enhancements include:

1. **Additional Controls**: Support for more security best practices and standards
2. **Multi-Account Support**: Scanning across multiple AWS accounts
3. **Enhanced Reporting**: More comprehensive reports and visualizations
4. **Integration with Security Hubs**: Feed compliance data to AWS Security Hub
5. **Custom Control Definitions**: Allow users to define custom compliance rules

---

## AI Assistance Acknowledgments

This project benefited from AI assistance from:

- **Gemini 2.5 Pro (Cursor AI)**: Assisted with code refactoring for performance and maintainability, Git operations, unit test implementation, and documentation updates.
- **Claude 3.7 Sonnet** - Helped optimize code structure, improve error handling, implement AWS service integration, and create documentation.
- **Grok 3** - Contributed to security rule implementation and compliance logic development.

---

*This detailed documentation was generated by Claude 3.7 Sonnet on behalf of the project owners.* 