import logging
import os
import uuid
import json
import boto3
import requests
import gzip
import urllib.parse
from io import BytesIO
from azure.identity import ManagedIdentityCredential
from datetime import datetime, timezone
import azure.functions as func
import hashlib
import hmac
import base64
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Function App instance
app = func.FunctionApp()

# Constants for timeout management
MAX_EXECUTION_TIME_SECONDS = 270  # 4.5 minutes (leave buffer before 5 min timeout)
MAX_RETRIES = 3
PARALLEL_S3_OPERATIONS = 5  # Process 5 S3 files concurrently
START_OF_DAY = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


def load_from_env_variables():
    """Load configuration from environment variables"""
    role_arn = os.environ.get('AWS_ROLE_ARN')
    logger.info(f"RoleARN: {role_arn}")
    queue_url = os.environ.get('C42_SQS_QUEUE_URL')
    logger.info(f"C42_queue_url: {queue_url}")
    region = os.environ.get('AWS_REGION', 'us-east-1')
    logger.info(f"region: {region}")
    bucket_name = os.environ.get('C42_bucket_name')
    logger.info(f"C42_bucket_name: {bucket_name}")
    return role_arn, queue_url, region, bucket_name


# --- AWS Authentication ---
def get_aws_credentials_from_oidc(role_arn, session_name='azure-function-session'):
    """Authenticate to AWS using Azure Managed Identity OIDC token"""
    try:
        credential = ManagedIdentityCredential()
        token = credential.get_token("https://management.azure.com/.default")
        oidc_token = token.token
        logger.info('OIDC token acquired successfully')

        client = boto3.client('sts')
        assumed_role = client.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            WebIdentityToken=oidc_token
        )
        logger.info("Assumed AWS role via STS")
        return assumed_role['Credentials']
    except Exception as e:
        logger.error(f"Failed to get AWS credentials: {e}")
        raise


# --- AWS Clients ---
def create_s3_client(credentials, region='us-east-1'):
    """Create S3 client with temporary credentials"""
    return boto3.client(
        's3',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region
    )


def create_sqs_client(credentials, region='us-east-1'):
    """Create SQS client with temporary credentials"""
    return boto3.client(
        'sqs',
        region_name=region,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )


def poll_message_from_sqs(queue_url, sqs_client, max_messages=10):
    """Poll messages from SQS queue"""
    try:
        response = sqs_client.receive_message(
            QueueUrl=queue_url,
            ReceiveRequestAttemptId=str(uuid.uuid4()),
            VisibilityTimeout=360,  # 6 minutes
            AttributeNames=['SentTimestamp'],
            MaxNumberOfMessages=max_messages,
            WaitTimeSeconds=5
        )
        messages = response.get('Messages', [])
        logger.info(f"Received {len(messages)} messages from SQS")
        return messages
    except Exception as e:
        logger.error(f"Error polling SQS: {e}")
        return []


# --- S3 Operations ---
def get_s3_file_metadata(s3_client, bucket, key):
    """Get S3 file metadata including size and last modified time"""
    try:
        response = s3_client.head_object(Bucket=bucket, Key=key)
        file_size_kb = response["ContentLength"] / 1024
        last_modified_utc = response["LastModified"].astimezone(timezone.utc)
        return file_size_kb, last_modified_utc
    except Exception as e:
        logger.error(f"Error getting metadata for {key}: {e}")
        raise


def s3_read_file_to_bytes(s3_client, bucket, key):
    """Read file content from S3"""
    try:
        logger.info(f"Reading content from S3: {key}")
        response = s3_client.get_object(Bucket=bucket, Key=urllib.parse.unquote(key))
        return response['Body'].read()
    except Exception as e:
        logger.error(f"Error reading S3 file {key}: {e}")
        raise


def handle_gz_files(bucket, key, sent_timestamp_ms, raw_bytes):
    """Decompress and parse gzip files"""
    logger.info(f"Decompressing Gzip file: {key}")
    output = []
    try:
        with gzip.GzipFile(fileobj=BytesIO(raw_bytes)) as gz:
            for line in gz.read().decode('utf-8').split('\n'):
                if not line.strip():
                    continue
                transformed_data = transform_to_standard_schema(
                    bucket, key, sent_timestamp_ms, json.loads(line)
                )
                output.append(transformed_data)
        return output
    except Exception as e:
        logger.error(f"Error processing gzip file {key}: {e}")
        raise


def handle_json_files(bucket, key, event_time, raw_bytes):
    """Parse JSON files"""
    logger.info(f"Processing JSON file: {key}")
    try:
        data = json.loads(raw_bytes)
        return transform_to_standard_schema(bucket, key, event_time, data)
    except Exception as e:
        logger.error(f"Error processing JSON file {key}: {e}")
        raise


def transform_to_standard_schema(bucket_name, prefix_key, event_time, json_data):
    """Transform data to standard schema for Log Analytics"""
    return {
        'Bucket_Name': bucket_name,
        'Key': prefix_key,
        'Actual_Time': event_time,
        'Raw_Data': json.dumps(json_data)
    }


# --- Process S3 File (for parallel execution) ---
def process_s3_file(s3_client, record):
    """Process a single S3 file record"""
    try:
        bucket = record.get('Bucket Name')
        key = record.get('Object Key')
        event_time = record.get('Event Time')

        if not key:
            logger.warning("Missing S3 key in record.")
            return []

        # Get file metadata
        size, last_modified_time = get_s3_file_metadata(s3_client, bucket, key)

        # Skip old files
        if (START_OF_DAY - last_modified_time).days > 0:
            logger.info(f"Skipping file {key} as it is older than today.")
            return []

        # Read file content
        content = s3_read_file_to_bytes(s3_client, bucket, key)

        # Process based on file type
        if key.endswith('.gz'):
            payload = handle_gz_files(bucket, key, event_time, content)
        elif key.endswith('.json'):
            payload = handle_json_files(bucket, key, event_time, content)
        else:
            logger.warning(f'Unsupported file type: {key}')
            return []

        # Normalize payload to list
        if isinstance(payload, list):
            return payload
        elif isinstance(payload, dict):
            return [payload]
        else:
            logger.warning("Unexpected payload type.")
            return []

    except Exception as e:
        logger.error(f"Error processing S3 file {record.get('Object Key')}: {e}")
        return []


# --- Azure Log Analytics ---
def chunk_list(lst, chunk_size):
    """Split list into chunks"""
    for i in range(0, len(lst), chunk_size):
        yield lst[i:i + chunk_size]


def build_signature(workspace_id, date, resource, content_length):
    """Build signature for Log Analytics API"""
    workspace_key = os.environ.get('LOG_ANALYTICS_SHARED_KEY')
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


def log_analytics_request_header(content_length, resource):
    """Create headers for Log Analytics request"""
    workspace_id = os.environ.get('LOG_ANALYTICS_WORKSPACE_ID')
    log_type = os.environ.get('C42_LOG_ANALYTICS_TABLE')
    rfc1123date = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
    signature = build_signature(workspace_id, rfc1123date, resource, content_length)

    headers = {
        'Content-Type': 'application/json',
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }
    return headers


async def send_to_log_analytics_async(data_as_list):
    """Send data to Log Analytics asynchronously with chunking"""
    workspace_id = os.environ.get('LOG_ANALYTICS_WORKSPACE_ID')
    resource = '/api/logs'
    uri = f"https://{workspace_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"

    chunk_size = int(os.environ.get('LOG_ANALYTICS_CHUNK_SIZE', 500))
    all_successful = True

    async with aiohttp.ClientSession() as session:
        for chunk in chunk_list(data_as_list, chunk_size):
            try:
                body = json.dumps(chunk)
                headers = log_analytics_request_header(len(body), resource)

                async with session.post(uri, data=body, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    if response.status == 200:
                        logger.info(f'Chunk of {len(chunk)} records sent to Log Analytics successfully.')
                    else:
                        response_text = await response.text()
                        logger.error(f'Failed to send chunk of {len(chunk)} records. '
                                   f'Status: {response.status}, Response: {response_text}')
                        all_successful = False
            except Exception as e:
                logger.error(f"Error sending chunk to Log Analytics: {e}")
                all_successful = False

    return all_successful


def send_to_log_analytics(data_as_list):
    """Synchronous wrapper for async Log Analytics send"""
    return asyncio.run(send_to_log_analytics_async(data_as_list))


# --- Main Function (V2) ---
@app.timer_trigger(schedule="0 */30 * * * *", arg_name="myTimer", run_on_startup=False, use_monitor=False)
def code42_sqs_to_loganalytics(myTimer: func.TimerRequest) -> None:
    """
    Azure Function V2 - Poll SQS and send S3 file contents to Log Analytics
    Runs every 30 minutes with timeout handling
    """
    start_time = datetime.now(timezone.utc)
    logger.info(f'Function triggered at {start_time}')

    if myTimer.past_due:
        logger.warning('The timer is past due!')

    try:
        # Load configuration
        role_arn, queue_url, region, bucket_name = load_from_env_variables()

        # Get AWS credentials
        creds = get_aws_credentials_from_oidc(role_arn)
        s3 = create_s3_client(creds, region)
        sqs = create_sqs_client(creds, region)

        sqs_msg_count = 0
        total_records = 0
        total_messages_deleted = 0

        # Create thread pool for parallel S3 operations
        executor = ThreadPoolExecutor(max_workers=PARALLEL_S3_OPERATIONS)

        # Process messages until timeout or queue empty
        while True:
            # Check if we're approaching timeout
            elapsed_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            if elapsed_time > MAX_EXECUTION_TIME_SECONDS:
                logger.warning(f"Approaching timeout limit. Stopping processing after {elapsed_time} seconds.")
                break

            # Poll messages
            messages = poll_message_from_sqs(queue_url, sqs)
            sqs_msg_count += len(messages)

            if not messages:
                logger.info("No more messages in the queue.")
                break

            # Process each message
            for msg in messages:
                try:
                    # Check timeout again
                    elapsed_time = (datetime.now(timezone.utc) - start_time).total_seconds()
                    if elapsed_time > MAX_EXECUTION_TIME_SECONDS:
                        logger.warning("Timeout limit reached during message processing.")
                        break

                    logger.info(f"Processing SQS message: {msg.get('MessageId')}")
                    records = json.loads(msg['Body'])

                    if not records:
                        logger.warning("No records found in message body.")
                        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg['ReceiptHandle'])
                        total_messages_deleted += 1
                        continue

                    # Normalize to list
                    if isinstance(records, dict):
                        records = [records]

                    # Process S3 files in parallel
                    log_entries = []
                    futures = []

                    for record in records:
                        future = executor.submit(process_s3_file, s3, record)
                        futures.append(future)

                    # Collect results
                    for future in futures:
                        try:
                            result = future.result(timeout=60)  # 60 second timeout per file
                            log_entries.extend(result)
                        except Exception as e:
                            logger.error(f"Error processing S3 file in parallel: {e}")

                    # Send to Log Analytics if we have data
                    if log_entries:
                        success = send_to_log_analytics(log_entries)
                        if success:
                            logger.info(f"Successfully sent {len(log_entries)} log entries.")
                            total_records += len(log_entries)
                            # Delete message after successful processing
                            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg['ReceiptHandle'])
                            total_messages_deleted += 1
                        else:
                            logger.error(f"Failed to send logs for message {msg.get('MessageId')}")
                    else:
                        # No log entries, still delete the message
                        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg['ReceiptHandle'])
                        total_messages_deleted += 1

                except Exception as e:
                    logger.error(f"Error processing message {msg.get('MessageId')}: {e}")
                    # Don't delete message on error - it will be reprocessed

        # Cleanup
        executor.shutdown(wait=False)

        # Final summary
        execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
        logger.info(f"Function execution completed in {execution_time:.2f} seconds")
        logger.info(f"Total SQS messages processed: {sqs_msg_count}")
        logger.info(f"Total SQS messages deleted: {total_messages_deleted}")
        logger.info(f"Total log records sent: {total_records}")

    except Exception as e:
        logger.error(f"Fatal error in function execution: {e}")
        raise