---
name: detecting-supply-chain-attacks-in-ci-cd
description: "'Scans GitHub Actions workflows and CI/CD pipeline configurations for"
version: 1.0.0
author: Anthropic-Cybersecurity-Skills (upstream) + mort install
license: MIT
sources: Anthropic-Cybersecurity-Skills
metadata:
  hermes:
    tags: [actions, and, configurations, detecting-supply-chain-attacks-in-ci-cd, for, github, pipeline, scans, workflows]
    related_skills: [pentest-ref-corpus, github-topic-crawl]
triggers: [detecting, supply, chain, attacks, actions, and, configurations, for, github, pipeline, scans, workflows]
---

<!-- upstream: Anthropic-Cybersecurity-Skills / detecting-supply-chain-attacks-in-ci-cd -->
<!-- original description: 'Scans GitHub Actions workflows and CI/CD pipeline configurations for -->

# Detecting Supply Chain Attacks in CI/CD


## When to Use

- When investigating security incidents that require detecting supply chain attacks in ci cd
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Scan CI/CD workflow files for supply chain risks by parsing GitHub Actions YAML,
checking for unpinned dependencies, script injection vectors, and secrets exposure.

```python
import yaml
from pathlib import Path

for wf in Path(".github/workflows").glob("*.yml"):
    with open(wf) as f:
        workflow = yaml.safe_load(f)
    for job_name, job in workflow.get("jobs", {}).items():
        for step in job.get("steps", []):
            uses = step.get("uses", "")
            if uses and "@" in uses and not uses.split("@")[1].startswith("sha"):
                print(f"Unpinned action: {uses} in {wf.name}")
```

Key supply chain risks:
1. Unpinned GitHub Actions (using @main instead of SHA)
2. Script injection via ${{ github.event }} expressions
3. Overly permissive GITHUB_TOKEN permissions
4. Third-party actions with write access to repo
5. Dependency confusion via public/private package name collision

## Examples

```python
# Check for script injection in run steps
for step in job.get("steps", []):
    run_cmd = step.get("run", "")
    if "${{" in run_cmd and "github.event" in run_cmd:
        print(f"Script injection risk: {run_cmd[:80]}")
```