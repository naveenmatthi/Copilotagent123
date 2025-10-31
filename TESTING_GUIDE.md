# Testing Guide - Code42 Function App

## Quick Test Commands

### 1. Test Locally

```powershell
# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Update local.settings.json with your values

# Start function locally
func start
```

### 2. Test AWS Authentication

```powershell
# Test script to verify AWS authentication
python -c @"
import boto3
from azure.identity import ManagedIdentityCredential
import os

# Set test environment
os.environ['AWS_ROLE_ARN'] = 'arn:aws:iam::YOUR_ACCOUNT:role/YOUR_ROLE'

# Test authentication
credential = ManagedIdentityCredential()
token = credential.get_token('https://management.azure.com/.default')
print(f'✓ Azure token acquired: {token.token[:20]}...')

# Test STS
client = boto3.client('sts')
assumed_role = client.assume_role_with_web_identity(
    RoleArn=os.environ['AWS_ROLE_ARN'],
    RoleSessionName='test-session',
    WebIdentityToken=token.token
)
print('✓ AWS role assumed successfully')
print(f'  Access Key: {assumed_role[\"Credentials\"][\"AccessKeyId\"]}')
"@
```

### 3. Test SQS Connection

```powershell
# Test SQS polling
python -c @"
import boto3
import os
from azure.identity import ManagedIdentityCredential

os.environ['AWS_ROLE_ARN'] = 'arn:aws:iam::YOUR_ACCOUNT:role/YOUR_ROLE'
os.environ['C42_SQS_QUEUE_URL'] = 'https://sqs.us-east-1.amazonaws.com/YOUR_ACCOUNT/YOUR_QUEUE'
os.environ['AWS_REGION'] = 'us-east-1'

# Get credentials
credential = ManagedIdentityCredential()
token = credential.get_token('https://management.azure.com/.default')
client = boto3.client('sts')
assumed_role = client.assume_role_with_web_identity(
    RoleArn=os.environ['AWS_ROLE_ARN'],
    RoleSessionName='test',
    WebIdentityToken=token.token
)
creds = assumed_role['Credentials']

# Test SQS
sqs = boto3.client('sqs',
    region_name=os.environ['AWS_REGION'],
    aws_access_key_id=creds['AccessKeyId'],
    aws_secret_access_key=creds['SecretAccessKey'],
    aws_session_token=creds['SessionToken']
)

response = sqs.receive_message(
    QueueUrl=os.environ['C42_SQS_QUEUE_URL'],
    MaxNumberOfMessages=1
)

messages = response.get('Messages', [])
print(f'✓ SQS connection successful')
print(f'  Messages available: {len(messages)}')
"@
```

### 4. Test S3 Access

```python
# test_s3.py
import boto3
from azure.identity import ManagedIdentityCredential
import os

os.environ['AWS_ROLE_ARN'] = 'YOUR_ROLE_ARN'
os.environ['AWS_REGION'] = 'us-east-1'
os.environ['C42_bucket_name'] = 'your-bucket'

# Authenticate
credential = ManagedIdentityCredential()
token = credential.get_token('https://management.azure.com/.default')
client = boto3.client('sts')
assumed_role = client.assume_role_with_web_identity(
    RoleArn=os.environ['AWS_ROLE_ARN'],
    RoleSessionName='test',
    WebIdentityToken=token.token
)
creds = assumed_role['Credentials']

# Test S3
s3 = boto3.client('s3',
    region_name=os.environ['AWS_REGION'],
    aws_access_key_id=creds['AccessKeyId'],
    aws_secret_access_key=creds['SecretAccessKey'],
    aws_session_token=creds['SessionToken']
)

# List objects
response = s3.list_objects_v2(
    Bucket=os.environ['C42_bucket_name'],
    MaxKeys=5
)

print('✓ S3 connection successful')
print(f'  Objects found: {response.get("KeyCount", 0)}')
if 'Contents' in response:
    for obj in response['Contents'][:3]:
        print(f'    - {obj["Key"]}')
```

### 5. Test Log Analytics Connection

```python
# test_log_analytics.py
import os
import json
import hashlib
import hmac
import base64
import requests
from datetime import datetime, timezone

os.environ['LOG_ANALYTICS_WORKSPACE_ID'] = 'your-workspace-id'
os.environ['LOG_ANALYTICS_SHARED_KEY'] = 'your-shared-key'
os.environ['C42_LOG_ANALYTICS_TABLE'] = 'Code42Logs'

def build_signature(workspace_id, date, resource, content_length, workspace_key):
    method = 'POST'
    content_type = 'application/json'
    x_headers = f'x-ms-date:{date}'
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_hash = bytes(string_to_hash, encoding='utf-8')
    decoded_key = base64.b64decode(workspace_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode()
    return f"SharedKey {workspace_id}:{encoded_hash}"

# Test data
test_data = [{
    'Message': 'Test message from Code42 Function',
    'Timestamp': datetime.now(timezone.utc).isoformat(),
    'Source': 'FunctionTest'
}]

workspace_id = os.environ['LOG_ANALYTICS_WORKSPACE_ID']
workspace_key = os.environ['LOG_ANALYTICS_SHARED_KEY']
log_type = os.environ['C42_LOG_ANALYTICS_TABLE']

resource = '/api/logs'
uri = f"https://{workspace_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"

body = json.dumps(test_data)
rfc1123date = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
signature = build_signature(workspace_id, rfc1123date, resource, len(body), workspace_key)

headers = {
    'Content-Type': 'application/json',
    'Authorization': signature,
    'Log-Type': log_type,
    'x-ms-date': rfc1123date
}

response = requests.post(uri, data=body, headers=headers)

if response.status_code == 200:
    print('✓ Log Analytics connection successful')
    print(f'  Test message sent to table: {log_type}_CL')
else:
    print(f'✗ Failed: Status {response.status_code}')
    print(f'  Response: {response.text}')
```

## Integration Testing

### Full End-to-End Test

```python
# test_full_flow.py
"""
Full integration test simulating the complete flow:
1. Create test SQS message
2. Add test S3 file
3. Trigger function
4. Verify Log Analytics entry
"""

import boto3
import json
import gzip
from io import BytesIO
from datetime import datetime, timezone

# Configuration
SQS_QUEUE_URL = 'your-sqs-queue-url'
S3_BUCKET = 'your-s3-bucket'
AWS_REGION = 'us-east-1'

# 1. Create test log file
test_logs = [
    {'event': 'test_event_1', 'timestamp': datetime.now(timezone.utc).isoformat()},
    {'event': 'test_event_2', 'timestamp': datetime.now(timezone.utc).isoformat()}
]

# Compress to gzip
buffer = BytesIO()
with gzip.GzipFile(fileobj=buffer, mode='w') as gz:
    gz.write('\n'.join([json.dumps(log) for log in test_logs]).encode('utf-8'))
compressed_data = buffer.getvalue()

# 2. Upload to S3
s3 = boto3.client('s3', region_name=AWS_REGION)
test_key = f'test-logs/test-{datetime.now().strftime("%Y%m%d%H%M%S")}.gz'
s3.put_object(Bucket=S3_BUCKET, Key=test_key, Body=compressed_data)
print(f'✓ Test file uploaded to S3: {test_key}')

# 3. Send SQS message
sqs = boto3.client('sqs', region_name=AWS_REGION)
message_body = json.dumps({
    'Bucket Name': S3_BUCKET,
    'Object Key': test_key,
    'Event Time': datetime.now(timezone.utc).isoformat()
})

sqs.send_message(QueueUrl=SQS_QUEUE_URL, MessageBody=message_body)
print('✓ SQS message sent')
print('\nWait for function to execute (next 30-min interval)')
print('Then check Log Analytics for entries with:')
print(f'  Key: {test_key}')
```

### Load Testing

```python
# load_test.py
"""
Create multiple SQS messages to test timeout handling
"""

import boto3
import json
from datetime import datetime, timezone

SQS_QUEUE_URL = 'your-sqs-queue-url'
S3_BUCKET = 'your-s3-bucket'
NUM_MESSAGES = 50  # Adjust based on your needs

sqs = boto3.client('sqs', region_name='us-east-1')

print(f'Sending {NUM_MESSAGES} test messages...')
for i in range(NUM_MESSAGES):
    message_body = json.dumps({
        'Bucket Name': S3_BUCKET,
        'Object Key': f'load-test/test-file-{i}.gz',
        'Event Time': datetime.now(timezone.utc).isoformat()
    })
    
    sqs.send_message(QueueUrl=SQS_QUEUE_URL, MessageBody=message_body)
    
    if (i + 1) % 10 == 0:
        print(f'  Sent {i + 1} messages...')

print(f'✓ All {NUM_MESSAGES} messages sent')
print('Monitor Application Insights for timeout warnings')
```

## Monitoring Queries

### Application Insights (Kusto)

```kusto
// Function execution times
traces
| where operation_Name == "code42_sqs_to_loganalytics"
| where message contains "Function execution completed"
| extend ExecutionTime = extract("completed in ([0-9.]+) seconds", 1, message)
| project timestamp, ExecutionTime = todouble(ExecutionTime)
| render timechart

// Timeout warnings
traces
| where message contains "timeout" or message contains "Approaching timeout"
| project timestamp, severityLevel, message
| order by timestamp desc

// Processing statistics
traces
| where message contains "Total log records sent"
| extend Records = extract("Total log records sent: (\\d+)", 1, message)
| extend Messages = extract("Total SQS messages processed: (\\d+)", 1, message)
| project timestamp, Records = toint(Records), Messages = toint(Messages)
| render timechart

// Error rate
traces
| where severityLevel >= 3  // Warning and above
| summarize ErrorCount = count() by bin(timestamp, 1h), severityLevel
| render timechart
```

### Log Analytics

```kusto
// Query custom logs table
Code42Logs_CL
| where TimeGenerated > ago(1h)
| take 10

// Count records by bucket
Code42Logs_CL
| where TimeGenerated > ago(24h)
| summarize Count = count() by Bucket_Name_s
| render piechart

// Recent files processed
Code42Logs_CL
| where TimeGenerated > ago(1h)
| distinct Key_s
| take 20
```

## Validation Checklist

Before deploying to production:

- [ ] Local function starts without errors
- [ ] Azure authentication succeeds (Managed Identity)
- [ ] AWS STS role assumption works
- [ ] SQS messages are received
- [ ] S3 files are downloaded
- [ ] Gzip files are decompressed correctly
- [ ] JSON parsing works
- [ ] Log Analytics uploads succeed
- [ ] SQS messages are deleted after success
- [ ] Timeout handling works (test with `MAX_EXECUTION_TIME_SECONDS=60`)
- [ ] Parallel processing works
- [ ] Error handling logs appropriately
- [ ] Application Insights shows telemetry

## Common Test Scenarios

### Scenario 1: Empty Queue
**Expected:** Function completes quickly, logs "No more messages"

### Scenario 2: Invalid S3 Key
**Expected:** Logs error, continues to next message, doesn't delete failed message

### Scenario 3: Large File (> 50MB)
**Expected:** Processes successfully or times out gracefully

### Scenario 4: Malformed JSON
**Expected:** Logs error, continues processing, doesn't crash

### Scenario 5: Log Analytics Unavailable
**Expected:** Retries, logs failure, doesn't delete SQS message

### Scenario 6: Approaching Timeout
**Expected:** Stops processing, logs warning, exits gracefully

## Performance Benchmarks

Track these metrics during testing:

| Metric | Target | Alert If |
|--------|--------|----------|
| Execution Time | < 4 min | > 4.5 min |
| Messages/Execution | 10-50 | < 5 |
| Records/Second | > 100 | < 50 |
| Success Rate | > 95% | < 90% |
| SQS Messages Deleted | 100% of successful | < 95% |

## Debugging Tips

### Enable Debug Logging
```python
# Add to function_app.py
logging.basicConfig(level=logging.DEBUG)
```

### View Live Logs
```powershell
# Azure
func azure functionapp logstream <function-app-name>

# Or in Portal: Function App > Functions > code42_sqs_to_loganalytics > Monitor > Logs
```

### Check Function Invocations
```powershell
# Recent invocations
az functionapp function show --name code42_sqs_to_loganalytics `
  --function-app-name <app-name> `
  --resource-group <rg-name>
```

### Manual Trigger (for testing)
```powershell
# Trigger via HTTP (if you add HTTP trigger)
Invoke-RestRequest -Uri "https://<function-app>.azurewebsites.net/api/code42_sqs_to_loganalytics" `
  -Method POST
```
