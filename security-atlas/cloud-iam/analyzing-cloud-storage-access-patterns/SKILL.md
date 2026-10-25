---
name: analyzing-cloud-storage-access-patterns
description: "Detect abnormal access AWS S3 GCS Azure Blob Storage."
version: 1.0.0
author: Anthropic-Cybersecurity-Skills (upstream) + mort install
license: MIT
sources: Anthropic-Cybersecurity-Skills
metadata:
  hermes:
    tags: [abnormal, access, after-hours, analytics, analyzing, analyzing-cloud-storage-access-patterns, and, anomaly, api-call, audit, aws, azure]
    related_skills: [pentest-ref-corpus, github-topic-crawl]
---

<!-- upstream: Anthropic-Cybersecurity-Skills / analyzing-cloud-storage-access-patterns -->
<!-- original description: Detect abnormal access in AWS S3, GCS, and Azure Blob Storage by analyzing CloudTrail Data Events, GCS audit logs, and Azure Storage Analytics for after-hours bulk downloads, new-IP access, and API-call spikes (e.g. GetObject) via statistical baselines and time-series anomaly detection. Use when investigating suspected cloud data exfiltration or building related detection rules. -->

# Analyzing Cloud Storage Access Patterns


## When to Use

- When investigating security incidents that require analyzing cloud storage access patterns
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Familiarity with cloud security concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install boto3 requests`
2. Query CloudTrail for S3 Data Events using AWS CLI or boto3.
3. Build access baselines: hourly request volume, per-user object counts, source IP history.
4. Detect anomalies:
   - After-hours access (outside 8am-6pm local time)
   - Bulk downloads: >100 GetObject calls from single principal in 1 hour
   - New source IPs not seen in the prior 30 days
   - ListBucket enumeration spikes (reconnaissance indicator)
5. Generate prioritized findings report.

```bash
python scripts/agent.py --bucket my-sensitive-data --hours-back 24 --output s3_access_report.json
```

## Examples

### CloudTrail S3 Data Event
```json
{"eventName": "GetObject", "requestParameters": {"bucketName": "sensitive-data", "key": "financials/q4.xlsx"},
 "sourceIPAddress": "203.0.113.50", "userIdentity": {"arn": "arn:aws:iam::123456789012:user/analyst"}}
```