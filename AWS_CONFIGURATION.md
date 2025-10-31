# AWS Configuration Guide

## Required AWS Setup

### 1. IAM Role for Azure OIDC Authentication

Create an IAM role that trusts Azure's OIDC provider.

#### Trust Policy (Trust Relationship)

Replace `<AZURE_TENANT_ID>` and `<MANAGED_IDENTITY_OBJECT_ID>`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<AWS_ACCOUNT_ID>:oidc-provider/sts.windows.net/<AZURE_TENANT_ID>/"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "sts.windows.net/<AZURE_TENANT_ID>/:aud": "https://management.azure.com/",
          "sts.windows.net/<AZURE_TENANT_ID>/:sub": "<MANAGED_IDENTITY_OBJECT_ID>"
        }
      }
    }
  ]
}
```

#### How to Get Values

**Azure Tenant ID:**
```powershell
az account show --query tenantId -o tsv
```

**Managed Identity Object ID:**
```powershell
az functionapp identity show `
  --name <function-app-name> `
  --resource-group <resource-group> `
  --query principalId -o tsv
```

### 2. IAM Permission Policy

Attach this policy to the IAM role for S3 and SQS access.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SQSAccess",
      "Effect": "Allow",
      "Action": [
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:GetQueueUrl"
      ],
      "Resource": "arn:aws:sqs:<REGION>:<ACCOUNT_ID>:<QUEUE_NAME>"
    },
    {
      "Sid": "S3ReadAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:ListBucket",
        "s3:HeadObject"
      ],
      "Resource": [
        "arn:aws:s3:::<BUCKET_NAME>",
        "arn:aws:s3:::<BUCKET_NAME>/*"
      ]
    }
  ]
}
```

**Minimal permissions (most restrictive):**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage"
      ],
      "Resource": "arn:aws:sqs:us-east-1:123456789012:code42-logs-queue"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:HeadObject"
      ],
      "Resource": "arn:aws:s3:::code42-logs-bucket/*"
    }
  ]
}
```

### 3. Create OIDC Provider (One-time setup)

If not already created, add Azure as an OIDC provider in AWS:

**Using AWS CLI:**
```bash
aws iam create-open-id-connect-provider \
  --url "https://sts.windows.net/<AZURE_TENANT_ID>/" \
  --client-id-list "https://management.azure.com/" \
  --thumbprint-list "626D44E704D1CEABE3BF0D53397464AC8080142C"
```

**Note:** The thumbprint value is standard for Azure AD.

**Verify provider:**
```bash
aws iam list-open-id-connect-providers
```

### 4. Complete AWS Setup Script

**PowerShell script to automate AWS setup:**

```powershell
# configure-aws.ps1
param(
    [Parameter(Mandatory=$true)]
    [string]$AwsAccountId,
    
    [Parameter(Mandatory=$true)]
    [string]$AzureTenantId,
    
    [Parameter(Mandatory=$true)]
    [string]$ManagedIdentityObjectId,
    
    [Parameter(Mandatory=$true)]
    [string]$RoleName,
    
    [Parameter(Mandatory=$true)]
    [string]$SqsQueueArn,
    
    [Parameter(Mandatory=$true)]
    [string]$S3BucketName
)

# Create trust policy
$trustPolicy = @{
    Version = "2012-10-17"
    Statement = @(
        @{
            Effect = "Allow"
            Principal = @{
                Federated = "arn:aws:iam::${AwsAccountId}:oidc-provider/sts.windows.net/${AzureTenantId}/"
            }
            Action = "sts:AssumeRoleWithWebIdentity"
            Condition = @{
                StringEquals = @{
                    "sts.windows.net/${AzureTenantId}/:aud" = "https://management.azure.com/"
                    "sts.windows.net/${AzureTenantId}/:sub" = $ManagedIdentityObjectId
                }
            }
        }
    )
} | ConvertTo-Json -Depth 10

# Save trust policy
$trustPolicy | Out-File -FilePath "trust-policy.json"

# Create permissions policy
$permissionsPolicy = @{
    Version = "2012-10-17"
    Statement = @(
        @{
            Sid = "SQSAccess"
            Effect = "Allow"
            Action = @("sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes")
            Resource = $SqsQueueArn
        },
        @{
            Sid = "S3ReadAccess"
            Effect = "Allow"
            Action = @("s3:GetObject", "s3:HeadObject", "s3:ListBucket")
            Resource = @(
                "arn:aws:s3:::${S3BucketName}",
                "arn:aws:s3:::${S3BucketName}/*"
            )
        }
    )
} | ConvertTo-Json -Depth 10

# Save permissions policy
$permissionsPolicy | Out-File -FilePath "permissions-policy.json"

Write-Host "Policy files created:" -ForegroundColor Green
Write-Host "  - trust-policy.json" -ForegroundColor Cyan
Write-Host "  - permissions-policy.json" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps (run in AWS CLI):" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Create OIDC provider (if not exists):" -ForegroundColor White
Write-Host "   aws iam create-open-id-connect-provider ``" -ForegroundColor Gray
Write-Host "     --url `"https://sts.windows.net/${AzureTenantId}/`" ``" -ForegroundColor Gray
Write-Host "     --client-id-list `"https://management.azure.com/`" ``" -ForegroundColor Gray
Write-Host "     --thumbprint-list `"626D44E704D1CEABE3BF0D53397464AC8080142C`"" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Create IAM role:" -ForegroundColor White
Write-Host "   aws iam create-role ``" -ForegroundColor Gray
Write-Host "     --role-name ${RoleName} ``" -ForegroundColor Gray
Write-Host "     --assume-role-policy-document file://trust-policy.json" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Attach permissions policy:" -ForegroundColor White
Write-Host "   aws iam put-role-policy ``" -ForegroundColor Gray
Write-Host "     --role-name ${RoleName} ``" -ForegroundColor Gray
Write-Host "     --policy-name Code42AccessPolicy ``" -ForegroundColor Gray
Write-Host "     --policy-document file://permissions-policy.json" -ForegroundColor Gray
Write-Host ""
Write-Host "4. Get Role ARN:" -ForegroundColor White
Write-Host "   aws iam get-role --role-name ${RoleName} --query Role.Arn" -ForegroundColor Gray
```

### 5. Verify AWS Configuration

**Test OIDC provider:**
```bash
aws iam get-open-id-connect-provider \
  --open-id-connect-provider-arn "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/sts.windows.net/<TENANT_ID>/"
```

**Test role:**
```bash
aws iam get-role --role-name <ROLE_NAME>
```

**Test SQS access:**
```bash
aws sqs receive-message \
  --queue-url <QUEUE_URL> \
  --max-number-of-messages 1
```

**Test S3 access:**
```bash
aws s3 ls s3://<BUCKET_NAME>/ --max-items 5
```

## SQS Configuration

### Queue Settings

Recommended settings for the SQS queue:

```json
{
  "VisibilityTimeout": "360",           // 6 minutes (> function timeout)
  "MessageRetentionPeriod": "345600",   // 4 days
  "ReceiveMessageWaitTimeSeconds": "5", // Long polling
  "MaximumMessageSize": "262144"        // 256 KB
}
```

**Create queue (AWS CLI):**
```bash
aws sqs create-queue \
  --queue-name code42-logs-queue \
  --attributes VisibilityTimeout=360,MessageRetentionPeriod=345600,ReceiveMessageWaitTimeSeconds=5
```

### Dead Letter Queue (Recommended)

Create a DLQ for failed messages:

```bash
# Create DLQ
aws sqs create-queue --queue-name code42-logs-dlq

# Get DLQ ARN
DLQ_ARN=$(aws sqs get-queue-attributes \
  --queue-url <DLQ_URL> \
  --attribute-names QueueArn \
  --query Attributes.QueueArn \
  --output text)

# Configure main queue to use DLQ
aws sqs set-queue-attributes \
  --queue-url <MAIN_QUEUE_URL> \
  --attributes "{\"RedrivePolicy\":\"{\\\"deadLetterTargetArn\\\":\\\"${DLQ_ARN}\\\",\\\"maxReceiveCount\\\":\\\"5\\\"}\"}"
```

## S3 Configuration

### Bucket Policy (if needed)

If using a separate AWS account for S3:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowCode42RoleAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<ACCOUNT_ID>:role/<ROLE_NAME>"
      },
      "Action": [
        "s3:GetObject",
        "s3:HeadObject"
      ],
      "Resource": "arn:aws:s3:::<BUCKET_NAME>/*"
    }
  ]
}
```

## Security Best Practices

### 1. Least Privilege
- Only grant necessary permissions
- Use specific resource ARNs, not wildcards
- Regularly review permissions

### 2. Condition Keys
Add additional security with condition keys:

```json
{
  "Condition": {
    "StringEquals": {
      "sts.windows.net/<TENANT_ID>/:aud": "https://management.azure.com/"
    },
    "IpAddress": {
      "aws:SourceIp": ["<AZURE_DATACENTER_IP_RANGE>"]
    }
  }
}
```

### 3. Session Duration
Limit session duration in trust policy:

```json
{
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "NumericLessThan": {
      "sts:DurationSeconds": "3600"
    }
  }
}
```

### 4. MFA (Optional)
For sensitive environments, require MFA:

```json
{
  "Condition": {
    "Bool": {
      "aws:MultiFactorAuthPresent": "true"
    }
  }
}
```

## Troubleshooting AWS Authentication

### Error: "Not authorized to perform sts:AssumeRoleWithWebIdentity"

**Check:**
1. OIDC provider exists
2. Trust policy includes correct tenant ID
3. Managed Identity Object ID is correct
4. Token audience is `https://management.azure.com/`

### Error: "Access Denied" on S3/SQS

**Check:**
1. IAM role has permissions policy attached
2. Resource ARNs are correct
3. Bucket policy allows access (if cross-account)

### Error: "OIDC provider not found"

**Solution:**
```bash
aws iam create-open-id-connect-provider \
  --url "https://sts.windows.net/<TENANT_ID>/" \
  --client-id-list "https://management.azure.com/" \
  --thumbprint-list "626D44E704D1CEABE3BF0D53397464AC8080142C"
```

## Testing AWS Configuration

**Complete test script:**

```python
# test_aws_config.py
import boto3
from azure.identity import ManagedIdentityCredential

# Configuration
ROLE_ARN = "arn:aws:iam::123456789012:role/Code42AzureRole"
QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/123456789012/code42-queue"
BUCKET = "code42-logs-bucket"

print("Testing AWS configuration...")
print("=" * 50)

# Step 1: Get Azure token
print("\n1. Getting Azure Managed Identity token...")
try:
    credential = ManagedIdentityCredential()
    token = credential.get_token("https://management.azure.com/.default")
    print(f"   ✓ Token acquired (length: {len(token.token)})")
except Exception as e:
    print(f"   ✗ Failed: {e}")
    exit(1)

# Step 2: Assume AWS role
print("\n2. Assuming AWS role via STS...")
try:
    sts = boto3.client('sts')
    assumed_role = sts.assume_role_with_web_identity(
        RoleArn=ROLE_ARN,
        RoleSessionName='test-session',
        WebIdentityToken=token.token
    )
    creds = assumed_role['Credentials']
    print(f"   ✓ Role assumed: {ROLE_ARN}")
    print(f"   Access Key ID: {creds['AccessKeyId']}")
except Exception as e:
    print(f"   ✗ Failed: {e}")
    exit(1)

# Step 3: Test SQS
print("\n3. Testing SQS access...")
try:
    sqs = boto3.client('sqs',
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken']
    )
    response = sqs.receive_message(QueueUrl=QUEUE_URL, MaxNumberOfMessages=1)
    print(f"   ✓ SQS accessible")
    print(f"   Messages: {len(response.get('Messages', []))}")
except Exception as e:
    print(f"   ✗ Failed: {e}")

# Step 4: Test S3
print("\n4. Testing S3 access...")
try:
    s3 = boto3.client('s3',
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken']
    )
    response = s3.list_objects_v2(Bucket=BUCKET, MaxKeys=1)
    print(f"   ✓ S3 accessible")
    print(f"   Objects: {response.get('KeyCount', 0)}")
except Exception as e:
    print(f"   ✗ Failed: {e}")

print("\n" + "=" * 50)
print("AWS configuration test complete!")
```

## Resource ARN Format Reference

| Resource | ARN Format |
|----------|-----------|
| IAM Role | `arn:aws:iam::<account-id>:role/<role-name>` |
| SQS Queue | `arn:aws:sqs:<region>:<account-id>:<queue-name>` |
| S3 Bucket | `arn:aws:s3:::<bucket-name>` |
| S3 Object | `arn:aws:s3:::<bucket-name>/<key>` |
| OIDC Provider | `arn:aws:iam::<account-id>:oidc-provider/sts.windows.net/<tenant-id>/` |
