# Architecture & Data Flow

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          AZURE ENVIRONMENT                          │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Azure Function App (Python V2)                              │  │
│  │  Runtime: Python 3.9+, Functions Host V4                     │  │
│  │                                                               │  │
│  │  ┌────────────────────────────────────────────────────────┐  │  │
│  │  │  Timer Trigger: Every 30 minutes                       │  │  │
│  │  │  Schedule: "0 */30 * * * *"                           │  │  │
│  │  └────────────────────────────────────────────────────────┘  │  │
│  │                         │                                     │  │
│  │                         ▼                                     │  │
│  │  ┌────────────────────────────────────────────────────────┐  │  │
│  │  │  Managed Identity (System-assigned)                    │  │  │
│  │  │  • Gets Azure AD token                                 │  │  │
│  │  │  • Used for AWS OIDC authentication                    │  │  │
│  │  └────────────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                           │                                         │
│                           │ OIDC Token                             │
│                           ▼                                         │
└─────────────────────────────────────────────────────────────────────┘
                            │
                            │ AssumeRoleWithWebIdentity
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           AWS ENVIRONMENT                           │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  AWS STS (Security Token Service)                          │    │
│  │  • Validates Azure OIDC token                              │    │
│  │  • Issues temporary AWS credentials (60 min)               │    │
│  └────────────────────────────────────────────────────────────┘    │
│                           │                                         │
│                           │ Temporary Credentials                   │
│                           ▼                                         │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    AWS Services Access                      │   │
│  │                                                             │   │
│  │  ┌──────────────────┐          ┌──────────────────┐       │   │
│  │  │  SQS Queue       │          │  S3 Bucket       │       │   │
│  │  │  • Poll messages │          │  • Code42 logs   │       │   │
│  │  │  • Visibility:   │          │  • .gz & .json   │       │   │
│  │  │    6 minutes     │          │    files         │       │   │
│  │  └──────────────────┘          └──────────────────┘       │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                            │
                            │ Log Data
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      AZURE LOG ANALYTICS                            │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │  Log Analytics Workspace                                   │    │
│  │  • Custom Table: Code42Logs_CL                            │    │
│  │  • HTTP Data Collector API                                │    │
│  │  • Batch size: 500 records/chunk                          │    │
│  └────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Processing Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│ PHASE 1: Initialization (< 5 seconds)                              │
└─────────────────────────────────────────────────────────────────────┘
    │
    ├─► Load environment variables
    ├─► Start execution timer
    ├─► Get Azure Managed Identity token
    ├─► Assume AWS role via STS
    ├─► Create S3 & SQS clients
    └─► Initialize ThreadPoolExecutor (5 workers)

┌─────────────────────────────────────────────────────────────────────┐
│ PHASE 2: Message Processing Loop                                   │
└─────────────────────────────────────────────────────────────────────┘
    │
    └─► WHILE (not timeout AND messages available)
         │
         ├─► Check elapsed time < 270 seconds ⏱️
         │   └─► If approaching timeout → Exit gracefully
         │
         ├─► Poll SQS (max 10 messages, 5s wait)
         │   └─► If empty → Exit loop
         │
         └─► FOR each message:
              │
              ├─► Parse message body (JSON)
              ├─► Extract S3 records
              │
              ├─► Process S3 files IN PARALLEL (5 concurrent) 🚀
              │   │
              │   └─► FOR each file (ThreadPoolExecutor):
              │        ├─► Get file metadata (size, timestamp)
              │        ├─► Skip if older than today
              │        ├─► Download from S3
              │        ├─► Decompress (.gz) or parse (.json)
              │        ├─► Transform to standard schema
              │        └─► Return log entries
              │
              ├─► Collect all results
              │
              ├─► Upload to Log Analytics (async) 📤
              │   │
              │   └─► Split into chunks (500 records)
              │        └─► FOR each chunk (async):
              │             ├─► Build signature (HMAC-SHA256)
              │             ├─► Create headers
              │             ├─► POST to Log Analytics API
              │             └─► Verify status 200
              │
              └─► IF upload successful:
                   └─► Delete SQS message ✅
                  ELSE:
                   └─► Leave in queue for retry ⚠️

┌─────────────────────────────────────────────────────────────────────┐
│ PHASE 3: Cleanup & Summary                                         │
└─────────────────────────────────────────────────────────────────────┘
    │
    ├─► Shutdown ThreadPoolExecutor
    ├─► Log execution statistics
    │   ├─► Total execution time
    │   ├─► Messages processed
    │   ├─► Messages deleted
    │   └─► Total records sent
    │
    └─► Exit (0)
```

---

## Message Flow Example

```
┌──────────────────────────────────────────────────────────────────┐
│ SQS Message Example                                              │
└──────────────────────────────────────────────────────────────────┘

{
  "Bucket Name": "code42-logs-bucket",
  "Object Key": "logs/2025/10/31/file-123.gz",
  "Event Time": "2025-10-31T12:30:45Z"
}

    │
    ▼

┌──────────────────────────────────────────────────────────────────┐
│ S3 File Download & Processing                                    │
└──────────────────────────────────────────────────────────────────┘

1. Get metadata:
   • Size: 2.5 MB
   • Last Modified: 2025-10-31 12:30:00 UTC ✓ (today)

2. Download file (2.5 MB compressed)

3. Decompress gzip → 12 MB uncompressed

4. Parse JSON (line-delimited):
   {"event": "file_access", "user": "john@example.com", ...}
   {"event": "file_download", "user": "jane@example.com", ...}
   ... (1000 log entries)

5. Transform each entry:
   {
     "Bucket_Name": "code42-logs-bucket",
     "Key": "logs/2025/10/31/file-123.gz",
     "Actual_Time": "2025-10-31T12:30:45Z",
     "Raw_Data": "{\"event\":\"file_access\", ...}"
   }

    │
    ▼

┌──────────────────────────────────────────────────────────────────┐
│ Log Analytics Upload                                             │
└──────────────────────────────────────────────────────────────────┘

1. Split 1000 entries → 2 chunks (500 each)

2. Chunk 1 (500 records):
   • Build HMAC signature
   • POST to Log Analytics API
   • Response: 200 OK ✓

3. Chunk 2 (500 records):
   • Build HMAC signature
   • POST to Log Analytics API
   • Response: 200 OK ✓

4. All successful → Delete SQS message

    │
    ▼

┌──────────────────────────────────────────────────────────────────┐
│ Log Analytics Table: Code42Logs_CL                              │
└──────────────────────────────────────────────────────────────────┘

TimeGenerated        | Bucket_Name_s       | Key_s               | Raw_Data_s
─────────────────────┼────────────────────┼────────────────────┼──────────────
2025-10-31 12:35:00 | code42-logs-bucket | logs/.../file-123.gz| {"event": ...}
2025-10-31 12:35:00 | code42-logs-bucket | logs/.../file-123.gz| {"event": ...}
... (1000 rows)
```

---

## Parallel Processing Visualization

```
┌─────────────────────────────────────────────────────────────────────┐
│ ThreadPoolExecutor - Parallel S3 Processing                        │
└─────────────────────────────────────────────────────────────────────┘

SQS Message contains 10 S3 file references:

Traditional Sequential (V1):          Parallel V2 (5 workers):
═══════════════════════              ═══════════════════════

File 1 ████████ (5s)                 Worker 1: File 1 ████████ (5s)
File 2 ████████ (5s)                 Worker 2: File 2 ████████ (5s)
File 3 ████████ (5s)                 Worker 3: File 3 ████████ (5s)
File 4 ████████ (5s)                 Worker 4: File 4 ████████ (5s)
File 5 ████████ (5s)                 Worker 5: File 5 ████████ (5s)
File 6 ████████ (5s)                           ┌─── Next batch
File 7 ████████ (5s)                 Worker 1: File 6 ████████ (5s)
File 8 ████████ (5s)                 Worker 2: File 7 ████████ (5s)
File 9 ████████ (5s)                 Worker 3: File 8 ████████ (5s)
File 10 ████████ (5s)                Worker 4: File 9 ████████ (5s)
                                     Worker 5: File 10 ████████ (5s)

Total: 50 seconds                    Total: 10 seconds
══════════════════                   ══════════════════

                    5x FASTER! 🚀
```

---

## Timeout Handling Mechanism

```
┌─────────────────────────────────────────────────────────────────────┐
│ Execution Timeline (5-minute Azure limit)                          │
└─────────────────────────────────────────────────────────────────────┘

0s                                                                  300s
├───────────────────────────────────────────────────────────────────┤
│                     Function Execution                             │
│                                                                    │
│  ┌────┐  ┌──────────────────────────────────┐  ┌────┐            │
│  │Init│  │   Process Messages Loop          │  │Exit│            │
│  └────┘  └──────────────────────────────────┘  └────┘            │
│                                                                    │
│         ◄──────── Safe Zone (270s) ──────────►                   │
│                                                  │                │
│                                            ⚠️ Warning Zone        │
│                                                                    │
├─────────────────────────────────────────────────┼────────────────┤
0s                                               270s             300s

MAX_EXECUTION_TIME_SECONDS = 270  (Safety buffer: 30s)

Processing stops at 270s:
├─► Current batch finishes
├─► Uploads complete
├─► Messages deleted
└─► Function exits gracefully

Remaining messages stay in SQS for next execution (30 min later)
```

---

## Error Handling Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│ File Processing Error Handling                                     │
└─────────────────────────────────────────────────────────────────────┘

Message with 5 files: [A, B, C, D, E]

┌─────┬─────┬─────┬─────┬─────┐
│  A  │  B  │  C  │  D  │  E  │
└─────┴─────┴─────┴─────┴─────┘
   ✓     ✗     ✓     ✓     ✓
  OK   ERROR  OK    OK    OK

Result:
├─► Files A, C, D, E processed successfully
├─► File B error logged (but doesn't fail entire batch)
├─► 4 files uploaded to Log Analytics
└─► SQS message still deleted (4/5 success is acceptable)

Alternative (strict mode - future enhancement):
└─► Don't delete message if ANY file fails
    └─► Entire batch retried next execution
```

---

## Data Schema Transformation

```
┌─────────────────────────────────────────────────────────────────────┐
│ From S3 to Log Analytics                                           │
└─────────────────────────────────────────────────────────────────────┘

INPUT (S3 JSON line):
{
  "event": "file_download",
  "user": "john@example.com",
  "file_name": "report.pdf",
  "timestamp": "2025-10-31T12:30:45Z",
  "ip_address": "192.168.1.100"
}

    │
    │ transform_to_standard_schema()
    ▼

OUTPUT (Log Analytics):
{
  "Bucket_Name": "code42-logs-bucket",
  "Key": "logs/2025/10/31/file-123.gz",
  "Actual_Time": "2025-10-31T12:30:45Z",
  "Raw_Data": "{\"event\":\"file_download\",\"user\":...}"
}

    │
    │ Ingested into Log Analytics
    ▼

STORED (Code42Logs_CL table):
┌──────────────────────┬─────────────────────┬──────────────────┬───────────┐
│ TimeGenerated        │ Bucket_Name_s       │ Key_s            │ Raw_Data_s│
├──────────────────────┼─────────────────────┼──────────────────┼───────────┤
│ 2025-10-31T12:35:00Z │ code42-logs-bucket │ logs/.../file... │ {"event...│
└──────────────────────┴─────────────────────┴──────────────────┴───────────┘

Note: '_s' suffix added by Log Analytics (string type)
      '_CL' suffix for custom log tables
```

---

## Scalability Characteristics

```
┌─────────────────────────────────────────────────────────────────────┐
│ Scalability Profile                                                │
└─────────────────────────────────────────────────────────────────────┘

Files per Message │ Records per File │ Total Records │ Est. Time │ Status
──────────────────┼──────────────────┼───────────────┼───────────┼────────
        10        │       100        │     1,000     │   ~30s    │ ✅ OK
        50        │       500        │    25,000     │   ~2m     │ ✅ OK
       100        │      1,000       │   100,000     │   ~4m     │ ⚠️ Close
       200        │      2,000       │   400,000     │   ~8m     │ ❌ Timeout

Scaling Options:

1. Horizontal (Recommended):
   └─► Increase execution frequency (every 15 min)
       └─► Smaller batches per execution

2. Vertical (Premium Plan):
   └─► Increase function timeout to 30 minutes
       └─► Adjust MAX_EXECUTION_TIME_SECONDS = 1800

3. Parallelization:
   └─► Increase PARALLEL_S3_OPERATIONS to 10+
       └─► Requires more CPU/memory

4. Architectural (Large Scale):
   └─► Use Durable Functions
       └─► Fan-out/fan-in pattern
       └─► Unlimited duration
```

---

## Security Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│ Security Flow                                                       │
└─────────────────────────────────────────────────────────────────────┘

Azure Function
      │
      ├─► System-assigned Managed Identity
      │   └─► No credentials in code
      │   └─► Automatic token rotation
      │
      ├─► Get Azure AD token
      │   └─► Audience: https://management.azure.com/
      │   └─► Valid: 1 hour
      │
      ├─► AWS STS AssumeRoleWithWebIdentity
      │   └─► Validates Azure token
      │   └─► Issues temporary credentials
      │   └─► Valid: 1 hour (configurable)
      │
      ├─► Access AWS Services
      │   └─► IAM Role: Code42AzureRole
      │   └─► Permissions: S3 read, SQS receive/delete
      │
      └─► Access Log Analytics
          └─► Workspace ID + Shared Key
          └─► HMAC-SHA256 signature per request
          └─► Stored in Function App settings (encrypted)

Trust Chain:
Azure AD → AWS IAM OIDC Provider → AWS IAM Role → S3/SQS
```

---

## Monitoring & Observability

```
┌─────────────────────────────────────────────────────────────────────┐
│ Telemetry & Logging                                                │
└─────────────────────────────────────────────────────────────────────┘

Application Insights
├─► Execution traces
├─► Performance metrics
├─► Exception tracking
└─► Custom events

Function Logs
├─► INFO: Normal operations
├─► WARNING: Approaching timeout, skipped files
├─► ERROR: Failed operations, retries
└─► DEBUG: Detailed processing info

Log Analytics
├─► Custom table: Code42Logs_CL
├─► All processed log entries
└─► Query with KQL

Metrics to Monitor:
├─► Execution duration (target: < 4 min)
├─► Success rate (target: > 95%)
├─► Records processed per execution
├─► SQS messages deleted vs received
└─► Error rate by type
```

---

This architecture provides:
✅ **High throughput** - Parallel processing
✅ **Fault tolerance** - Individual file error handling
✅ **Data safety** - Only delete messages after success
✅ **Scalability** - Multiple tuning options
✅ **Security** - No credentials in code, managed identities
✅ **Observability** - Comprehensive logging and monitoring
