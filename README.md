# Code42 S3 to Log Analytics - Azure Function V2

## Overview
This Azure Function polls messages from an AWS SQS queue, retrieves Code42 log files from S3, and sends them to Azure Log Analytics. 

**Version 2** includes significant improvements for timeout handling and performance optimization.

## Key Features

### ✅ V2 Programming Model
- Fully migrated to Azure Functions Python V2 programming model
- Uses `@app.timer_trigger` decorator
- Improved code organization and maintainability

### ⚡ Performance & Timeout Improvements

#### 1. **Parallel S3 Processing**
- Processes up to 5 S3 files concurrently using `ThreadPoolExecutor`
- Reduces total processing time significantly

#### 2. **Async Log Analytics Upload**
- Uses `aiohttp` for asynchronous HTTP requests
- Faster data ingestion to Log Analytics

#### 3. **Intelligent Timeout Management**
- Monitors execution time with `MAX_EXECUTION_TIME_SECONDS = 270` (4.5 minutes)
- Gracefully stops processing before Azure's 5-minute timeout
- Prevents partial processing and data loss

#### 4. **Optimized Message Handling**
- Only deletes SQS messages after successful Log Analytics upload
- Failed messages remain in queue for retry
- Prevents data loss during failures

#### 5. **Better Error Handling**
- Individual file failures don't stop the entire batch
- Comprehensive logging for troubleshooting
- Structured exception handling

## Architecture

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐      ┌──────────────────┐
│   Timer     │─────▶│  Function   │─────▶│   AWS SQS   │─────▶│   AWS S3 Logs    │
│ (30 min)    │      │  (V2 Model) │      │   Queue     │      │  (.gz/.json)     │
└─────────────┘      └─────────────┘      └─────────────┘      └──────────────────┘
                            │                                              │
                            │                                              │
                            ▼                                              ▼
                  ┌──────────────────┐                        ┌─────────────────┐
                  │  Azure Managed   │                        │  Parallel S3    │
                  │    Identity      │                        │   Processing    │
                  │   (OIDC Auth)    │                        │ (5 concurrent)  │
                  └──────────────────┘                        └─────────────────┘
                            │                                              │
                            │                                              │
                            ▼                                              ▼
                  ┌──────────────────┐                        ┌─────────────────┐
                  │  AWS STS Role    │                        │  Transform &    │
                  │    Assumption    │                        │   Parse Logs    │
                  └──────────────────┘                        └─────────────────┘
                                                                          │
                                                                          │
                                                                          ▼
                                                              ┌──────────────────┐
                                                              │   Async Upload   │
                                                              │  to Log Analytics│
                                                              └──────────────────┘
```

## Configuration

### Environment Variables

Add these to your Function App Configuration (or `local.settings.json` for local testing):

| Variable | Description | Example |
|----------|-------------|---------|
| `AWS_ROLE_ARN` | AWS IAM Role ARN for STS assumption | `arn:aws:iam::123456789:role/Code42Role` |
| `AWS_REGION` | AWS Region | `us-east-1` |
| `C42_SQS_QUEUE_URL` | SQS Queue URL | `https://sqs.us-east-1.amazonaws.com/123/queue` |
| `C42_bucket_name` | S3 Bucket name | `code42-logs-bucket` |
| `LOG_ANALYTICS_WORKSPACE_ID` | Log Analytics Workspace ID | `abc12345-...` |
| `LOG_ANALYTICS_SHARED_KEY` | Log Analytics Primary/Secondary Key | `base64-encoded-key` |
| `C42_LOG_ANALYTICS_TABLE` | Custom Log table name | `Code42Logs_CL` |
| `LOG_ANALYTICS_CHUNK_SIZE` | Records per batch (default: 500) | `500` |

### Timer Schedule

The function runs every 30 minutes:
- Schedule: `0 */30 * * * *` (NCRONTAB format)
- Modify in `function_app.py` line with `@app.timer_trigger(schedule=...)`

## Deployment

### Prerequisites
1. Azure Function App (Python 3.9+)
2. Azure Managed Identity enabled on Function App
3. AWS IAM Role with:
   - Trust relationship for Azure (OIDC)
   - Permissions for SQS and S3
4. Azure Log Analytics Workspace

### Steps

#### 1. Install Azure Functions Core Tools
```powershell
# Install via npm
npm install -g azure-functions-core-tools@4 --unsafe-perm true

# Or via Chocolatey
choco install azure-functions-core-tools-4
```

#### 2. Install Dependencies Locally
```powershell
# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt
```

#### 3. Configure Local Settings
Update `local.settings.json` with your values.

#### 4. Test Locally
```powershell
func start
```

#### 5. Deploy to Azure
```powershell
# Login to Azure
az login

# Deploy function
func azure functionapp publish <YOUR_FUNCTION_APP_NAME>
```

#### 6. Configure Azure Settings
```powershell
# Set environment variables
az functionapp config appsettings set --name <YOUR_FUNCTION_APP_NAME> \
  --resource-group <YOUR_RESOURCE_GROUP> \
  --settings "AWS_ROLE_ARN=arn:aws:iam::..." \
             "C42_SQS_QUEUE_URL=https://sqs..." \
             "LOG_ANALYTICS_WORKSPACE_ID=..." \
             "LOG_ANALYTICS_SHARED_KEY=..."
```

## Performance Tuning

### For Large Log Volumes

#### 1. Adjust Parallel Processing
```python
PARALLEL_S3_OPERATIONS = 10  # Increase from 5 to 10
```

#### 2. Optimize Chunk Size
```python
# In environment variables
LOG_ANALYTICS_CHUNK_SIZE=1000  # Increase from 500
```

#### 3. Increase Function Timeout (Consumption Plan)
```json
// host.json
"functionTimeout": "00:10:00"  // Premium/Dedicated plans only
```

#### 4. Consider Premium Plan
- For processing times > 5 minutes
- Better performance and scaling
- No cold start delays

### For Timeout Issues

If still experiencing timeouts:

1. **Reduce SQS batch size**: Process fewer messages per execution
2. **Increase execution frequency**: Run every 15 minutes instead of 30
3. **Filter old files earlier**: Skip processing in SQS message itself
4. **Use Durable Functions**: For workflows > 10 minutes

## Monitoring

### Application Insights Queries

#### Success Rate
```kusto
traces
| where message contains "Function execution completed"
| summarize Count=count() by bin(timestamp, 1h)
```

#### Processing Metrics
```kusto
traces
| where message contains "Total log records sent"
| extend Records = extract("Total log records sent: (\\d+)", 1, message)
| summarize TotalRecords=sum(toint(Records)) by bin(timestamp, 1h)
```

#### Timeout Warnings
```kusto
traces
| where message contains "timeout"
| project timestamp, severityLevel, message
```

## Troubleshooting

### Issue: Function Times Out
**Solution:** 
- Check `MAX_EXECUTION_TIME_SECONDS` setting
- Reduce SQS message batch size
- Increase `PARALLEL_S3_OPERATIONS`
- Consider Premium plan

### Issue: AWS Authentication Fails
**Solution:**
- Verify Managed Identity is enabled
- Check AWS IAM Role trust policy includes Azure OIDC
- Validate `AWS_ROLE_ARN` format

### Issue: Log Analytics Upload Fails
**Solution:**
- Verify `LOG_ANALYTICS_WORKSPACE_ID` and `LOG_ANALYTICS_SHARED_KEY`
- Check table name format (must end with `_CL` for custom logs)
- Reduce `LOG_ANALYTICS_CHUNK_SIZE`

### Issue: SQS Messages Not Deleted
**Solution:**
- Check visibility timeout (currently 360 seconds)
- Ensure Log Analytics upload succeeds
- Review error logs for exceptions

## Major Changes from V1 to V2

| Aspect | V1 | V2 |
|--------|----|----|
| Programming Model | V1 (`@app.route`) | V2 (`@app.timer_trigger`) |
| S3 Processing | Sequential | Parallel (5 concurrent) |
| Log Analytics Upload | Synchronous | Asynchronous (aiohttp) |
| Timeout Handling | None | Intelligent monitoring & graceful stop |
| Error Handling | Retry entire message | Process individual files |
| Message Deletion | On attempt | On success only |
| Logging | Basic | Structured with context |
| Performance | Slow for large batches | Optimized for volume |

## Best Practices

1. **Monitor execution time** - Set up alerts for functions approaching timeout
2. **Use Application Insights** - Enable for detailed telemetry
3. **Test with production volume** - Validate performance with realistic data
4. **Configure alerts** - Set up alerts for failures and slow executions
5. **Regular dependency updates** - Keep Azure Functions runtime and packages updated

## Additional Resources

- [Azure Functions Python Developer Guide](https://learn.microsoft.com/azure/azure-functions/functions-reference-python)
- [Azure Functions Best Practices](https://learn.microsoft.com/azure/azure-functions/functions-best-practices)
- [Log Analytics Data Collector API](https://learn.microsoft.com/azure/azure-monitor/logs/data-collector-api)
- [AWS STS AssumeRoleWithWebIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html)

## Support

For issues or questions:
1. Check Application Insights logs
2. Review error messages in Azure Portal
3. Validate all environment variables
4. Test AWS connectivity separately

---

**Version:** 2.0  
**Last Updated:** October 2025  
**Python Version:** 3.9+  
**Azure Functions Runtime:** V4
