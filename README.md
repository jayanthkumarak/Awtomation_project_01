# CIS AWS Foundations Benchmark Compliance Checker

This project implements an AWS Lambda-based solution for checking and remediating AWS account compliance with the CIS AWS Foundations Benchmark v3.0. The solution evaluates various AWS services and configurations, such as IAM, S3, EC2, RDS, CloudTrail, and more, to ensure they meet security best practices.

## Architecture

![Architecture Diagram](https://mermaid.ink/img/pako:eNqVksFuwjAMhl_F8nnSQOihm7SNw6RJcEEcfEuQWtEQ1CRVmmrA3s1dgVIGndj5k-PPvx3nBEVRE0RQCldbo2XJlVkY3jJRu6_eVZJbJe3JWuuFdMfgvEqFxGp_GQWrnV7jilv3Oopee2clp_7Ec7KyzLO-dKMNp33V9lm5QDMz1pj-qIrLnD24KiN50I3CpNq5QpC-RWd7iKlp2bKcXUTnxcxKcVybWc4kOm8vNZqsWtOJf37x3k-NkvJYHvWYLu3zV9Pwe3eQnDXDU8-QTzDvtpvdwdzJrRtafcL9ZmwOd5zTe2_9n6bZPvU-B89HQw-hxVNSl-8d5FAQZkv-LDQRGKlLh1X3eo_qnAVsn7E52Ey4FAxiNHQTGlYJrG-FKTEH0ygNc04F5KDFptU6WONyXhBMzAXpH3Wf-7-i0iMIoZDKXQ1EsLy_AVQ8iJ8?type=png)

## Components

### Lambda Function (`aws_checker_in_lambda.py`)
The core component that:
- Evaluates compliance with CIS AWS Foundations Benchmark v3.0
- Provides remediation capabilities for non-compliant resources
- Generates HTML reports stored in S3
- Has comprehensive error handling and logging

### Control Definitions (`controls.json`)
A JSON file that defines all the controls to check, including:
- Human-readable names
- Descriptions
- Severity levels
- Compliance frameworks (CIS, NIST)
- Categories
- Remediation availability

### Infrastructure as Code (`sam.yaml`)
An AWS SAM template that provisions all required resources:
- Lambda function with appropriate permissions
- S3 buckets for reports and backups
- CloudWatch alarms for monitoring
- CloudWatch dashboard for visualization
- SNS topic for dead letter queue
- Daily schedule for automated scanning

## Features

- **Comprehensive Compliance Checking**: Evaluates 34 controls from the CIS AWS Foundations Benchmark v3.0
- **Automated Remediation**: Provides capability to fix non-compliant resources
- **Report Generation**: Creates HTML reports with compliance status
- **Monitoring**: CloudWatch alarms for error alerting
- **Visualization**: Dashboard for compliance status tracking
- **Scheduled Execution**: Daily automated checks

## Prerequisites

- AWS CLI installed and configured
- AWS SAM CLI installed
- Python 3.9 or higher
- Access to create and manage AWS resources

## Deployment

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cis-compliance-checker.git
   cd cis-compliance-checker
   ```

2. Create the S3 buckets for deployment:
   ```bash
   aws s3 mb s3://cis-compliance-reports
   aws s3 mb s3://cis-compliance-backups
   ```

3. Upload the controls definition:
   ```bash
   aws s3 cp controls.json s3://cis-compliance-reports/controls.json
   ```

4. Deploy the SAM template:
   ```bash
   sam build
   sam deploy --guided
   ```

   When prompted, provide the following information:
   - Stack Name: `cis-compliance-checker`
   - AWS Region: Your preferred region
   - Parameter ReportBucket: `cis-compliance-reports`
   - Parameter BackupBucket: `cis-compliance-backups`
   - Parameter LogLevel: `INFO`
   - Confirm other parameters as needed

## Usage

### API Endpoint

After deployment, you can invoke the API endpoint to run compliance checks or remediation:

```bash
# Run compliance evaluation
curl -X POST https://your-api-gateway-url/Prod/evaluate -d '{}'

# Run remediation for a specific control
curl -X POST https://your-api-gateway-url/Prod/remediate -d '{"action": "remediate", "control_id": "CloudTrail.2", "dry_run": true}'
```

### AWS Console

1. Navigate to the Lambda console
2. Find the `CISComplianceChecker` function
3. You can test it with a sample event like:
   ```json
   {
     "action": "evaluate"
   }
   ```

### CloudWatch Dashboard

A CloudWatch dashboard is created automatically. You can access it at:
`https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#dashboards:name=CIS-Compliance-Dashboard`

## Control Checks

The solution checks compliance with 34 controls from the CIS AWS Foundations Benchmark v3.0, including:
- IAM password policies and user management
- CloudTrail configuration and encryption
- S3 bucket security and encryption
- EC2 security groups and metadata service configuration
- RDS encryption and access controls
- KMS key rotation
- EFS encryption
- and more

## Remediation Capabilities

The solution can remediate certain non-compliant resources, such as:
- Enabling CloudTrail encryption
- Updating IAM password policies
- Blocking public access to S3 buckets

**Note**: Some remediation actions require manual intervention and are not automatically performed.

## Security Considerations

- The Lambda function uses least privilege IAM permissions
- All S3 buckets have encryption and versioning enabled
- No public access is allowed to any resources
- Sensitive actions require explicit confirmation

## Development

### Adding a New Control

1. Update `controls.json` with the new control definition
2. Add a new check function in `aws_checker_in_lambda.py`
3. Optionally, add a remediation function if automatic remediation is possible

### Extending Remediation

To add remediation for a new control:
1. Create a function named `remediate_{control_id.lower().replace('.', '_')}`
2. Implement the remediation logic with dry-run and confirmation params
3. Update the IAM permissions in `sam.yaml` if needed

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgements

- AWS for providing the serverless platform
- Center for Internet Security for the CIS AWS Foundations Benchmark
