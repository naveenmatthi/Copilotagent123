# Code42 Function App - Configuration Guide

## Timeout Configuration Strategy

### Problem
When processing large volumes of logs every 30 minutes, the function times out before completing all work.

### Solutions Implemented

#### 1. Time-Based Circuit Breaker (Primary Solution)
The function now monitors its execution time and stops processing before hitting Azure's timeout:

```python
MAX_EXECUTION_TIME_SECONDS = 270  # 4.5 minutes (30-second buffer)
```

**How it works:**
- Function checks elapsed time before processing each message
- Gracefully stops when approaching timeout
- Remaining messages stay in SQS queue for next execution

#### 2. Parallel Processing
Multiple S3 files are processed concurrently:

```python
PARALLEL_S3_OPERATIONS = 5  # Process 5 files at once
```

**Tuning:**
- **High CPU/Memory:** Increase to 8-10
- **Limited Resources:** Decrease to 3
- **Monitor:** Application Insights for optimal value

#### 3. Asynchronous Uploads
Log Analytics uploads use async HTTP for better throughput:

```python
async def send_to_log_analytics_async(data_as_list):
    async with aiohttp.ClientSession() as session:
        # Concurrent uploads
```

### Additional Recommendations

#### Option A: Increase Function Frequency (Recommended)
Instead of processing every 30 minutes, run every 15 minutes:

```python
@app.timer_trigger(schedule="0 */15 * * * *", ...)  # Every 15 min
```

**Benefits:**
- Smaller batches per execution
- Less chance of timeout
- More frequent processing

#### Option B: Use Premium Plan
Upgrade from Consumption to Premium plan for longer timeouts:

| Plan | Max Timeout |
|------|-------------|
| Consumption | 5 minutes (default) |
| Consumption | 10 minutes (max) |
| Premium | 30 minutes (default) |
| Premium | Unlimited (configured) |

**Configuration for Premium:**
```json
// host.json
{
  "functionTimeout": "00:30:00"  // 30 minutes
}
```

#### Option C: Use Durable Functions
For very large workloads, consider Durable Functions pattern:

**Benefits:**
- Can run for hours/days
- Automatic checkpointing
- Resilient to failures
- Fan-out/fan-in patterns

**Example:**
```python
@app.orchestration_trigger()
def orchestrator(context):
    # Get SQS messages
    messages = yield context.call_activity('get_sqs_messages')
    
    # Process in parallel
    tasks = [context.call_activity('process_message', msg) for msg in messages]
    yield context.task_all(tasks)
```

### Monitoring Timeout Issues

#### Application Insights Query
```kusto
traces
| where message contains "timeout" or message contains "Approaching timeout"
| project timestamp, severityLevel, message, operation_Name
| order by timestamp desc
```

#### Custom Metrics
Add to your Function App settings:
```json
{
  "APPINSIGHTS_INSTRUMENTATIONKEY": "your-key",
  "APPLICATIONINSIGHTS_ENABLE_LOGGING_SEVERITY_LEVEL": "Information"
}
```

### SQS Visibility Timeout

Current setting: **360 seconds (6 minutes)**

**Important:** Adjust if function timeout changes:
- Should be > Function timeout
- Prevents duplicate processing
- Current: 6 min (safe for 5 min function)

**Update in code:**
```python
response = sqs.receive_message(
    VisibilityTimeout=600,  # 10 minutes for Premium plan
    ...
)
```

### Performance Benchmarks

Based on typical workloads:

| Scenario | Files/Batch | Records/File | Time | Status |
|----------|-------------|--------------|------|--------|
| Small | 10 | 100 | ~30s | ✅ OK |
| Medium | 50 | 500 | ~2m | ✅ OK |
| Large | 100 | 1000 | ~4m | ⚠️ Close |
| Very Large | 200 | 2000 | ~8m | ❌ Timeout |

### Optimization Checklist

- [ ] Set `MAX_EXECUTION_TIME_SECONDS` to 270 (default)
- [ ] Configure `PARALLEL_S3_OPERATIONS` based on resources
- [ ] Set `LOG_ANALYTICS_CHUNK_SIZE` to 500-1000
- [ ] Enable Application Insights
- [ ] Monitor execution duration
- [ ] Consider Premium plan if consistently timing out
- [ ] Adjust timer frequency if needed
- [ ] Update SQS visibility timeout to match function timeout

### Testing Timeout Handling

#### Local Test
```powershell
# Set short timeout for testing
$env:MAX_EXECUTION_TIME_SECONDS="60"  # 1 minute

# Run function
func start
```

#### Load Test
```python
# Create test SQS messages
import boto3
import json

sqs = boto3.client('sqs')
for i in range(100):  # Simulate 100 messages
    sqs.send_message(
        QueueUrl='your-queue-url',
        MessageBody=json.dumps({
            'Bucket Name': 'test-bucket',
            'Object Key': f'test-file-{i}.gz',
            'Event Time': '2025-10-31T12:00:00Z'
        })
    )
```

### Emergency Timeout Mitigation

If experiencing immediate timeout issues:

1. **Temporarily reduce batch size:**
   ```python
   MaxNumberOfMessages=5  # Reduce from 10
   ```

2. **Increase execution frequency:**
   ```python
   schedule="0 */10 * * * *"  # Every 10 minutes
   ```

3. **Skip large files:**
   ```python
   MAX_FILE_SIZE_MB = 10  # Skip files larger than 10MB
   
   if file_size_kb / 1024 > MAX_FILE_SIZE_MB:
       logger.warning(f"Skipping large file: {key}")
       continue
   ```

## Environment-Specific Configuration

### Development
```json
{
  "MAX_EXECUTION_TIME_SECONDS": "60",
  "PARALLEL_S3_OPERATIONS": "2",
  "LOG_ANALYTICS_CHUNK_SIZE": "100"
}
```

### Production
```json
{
  "MAX_EXECUTION_TIME_SECONDS": "270",
  "PARALLEL_S3_OPERATIONS": "5",
  "LOG_ANALYTICS_CHUNK_SIZE": "500"
}
```

### High-Volume Production
```json
{
  "MAX_EXECUTION_TIME_SECONDS": "1800",  // Premium plan
  "PARALLEL_S3_OPERATIONS": "10",
  "LOG_ANALYTICS_CHUNK_SIZE": "1000"
}
```
