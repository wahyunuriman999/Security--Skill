---
name: implementing-endpoint-detection-with-wazuh
description: "Deploys and configures Wazuh SIEM/XDR for endpoint detection, covering agent authentication and management, custom decoder and rule XML creation, alert querying via the Wazuh REST API, rule testing with wazuh-logtest, and automated active-response actions. Use when setting up endpoint detection and response, writing or testing custom Wazuh rules, or querying and triaging Wazuh alerts."
version: 1.0.0
author: Anthropic-Cybersecurity-Skills (upstream) + mort install
license: MIT
sources: Anthropic-Cybersecurity-Skills
metadata:
  hermes:
    tags: [actions, active-response, agent, alert, and, api, authentication, automated, configures, covering, creation, custom]
    related_skills: [pentest-ref-corpus, github-topic-crawl]
triggers: [implementing, endpoint, detection, with, wazuh, actions, active-response, agent, alert, and, api, authentication, automated, configures, covering, creation]
---

<!-- upstream: Anthropic-Cybersecurity-Skills / implementing-endpoint-detection-with-wazuh -->
<!-- original description: Deploys and configures Wazuh SIEM/XDR for endpoint detection, covering agent authentication and management, custom decoder and rule XML creation, alert querying via the Wazuh REST API, rule testing with wazuh-logtest, and automated active-response actions. Use when setting up endpoint detection and response, writing or testing custom Wazuh rules, or querying and triaging Wazuh alerts. -->

# Implementing Endpoint Detection with Wazuh

## Overview

Wazuh is an open-source SIEM and XDR platform for endpoint monitoring, threat detection, and compliance. This skill covers managing agents via the Wazuh REST API, creating custom decoders and rules in XML for organization-specific detections, querying alerts, and testing rule logic using the logtest endpoint.


## When to Use

- When deploying or configuring implementing endpoint detection with wazuh capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Wazuh Manager 4.x deployed with API enabled
- Python 3.9+ with `requests` library
- API credentials (username/password for JWT authentication)
- Understanding of Wazuh decoder and rule XML syntax

## Steps

### Step 1: Authenticate to Wazuh API
Obtain JWT token via POST to /security/user/authenticate.

### Step 2: List and Monitor Agents
Query agent status, versions, and last keep-alive via /agents endpoint.

### Step 3: Query Security Alerts
Search alerts by rule ID, severity, agent, or time range.

### Step 4: Test Custom Rules with Logtest
Use the /logtest endpoint to validate decoder and rule logic against sample log lines.

## Expected Output

JSON report with agent inventory, alert statistics, rule coverage, and logtest validation results.