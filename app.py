# app.py
import os
import hmac
import hashlib
import json
import logging
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from flask import Flask, request, abort
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler

from config import USER_MAPPING, REMINDER_DELAY_HOURS, REMINDER_INTERVAL_HOURS
import gemini_service

# --- Initialization ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()

# Validate required environment variables
required_env_vars = ['SLACK_BOT_TOKEN', 'GITHUB_WEBHOOK_SECRET', 'GEMINI_API_KEY']
missing_vars = [var for var in required_env_vars if not os.environ.get(var)]
if missing_vars:
    logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
    sys.exit(1)

app = Flask(__name__)

# Slack client
slack_token = os.environ["SLACK_BOT_TOKEN"]
try:
    slack_client = WebClient(token=slack_token)
    # Test connection
    slack_client.auth_test()
except SlackApiError as e:
    logger.error(f"Failed to initialize Slack client: {e}")
    sys.exit(1)

# GitHub webhook secret
github_secret = os.environ["GITHUB_WEBHOOK_SECRET"].encode('utf-8')

# Scheduler for reminders
scheduler = BackgroundScheduler()
scheduler.start()

# Rate limiting (simple in-memory store)
from collections import defaultdict
request_counts = defaultdict(int)
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 100


# --- Security ---
def is_rate_limited(client_ip: str) -> bool:
    """Simple rate limiting check."""
    current_time = datetime.now()
    
    # Clean old entries
    cutoff_time = current_time - timedelta(seconds=RATE_LIMIT_WINDOW)
    
    # This is a simplified implementation - in production, use Redis or similar
    request_counts[client_ip] += 1
    if request_counts[client_ip] > RATE_LIMIT_MAX_REQUESTS:
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        return True
    
    return False

def verify_github_signature(payload_body: bytes, signature_header: str) -> bool:
    """Verify that the payload was sent from GitHub by validating the signature."""
    if not signature_header:
        logger.warning("No X-Hub-Signature-256 header on request.")
        return False
    
    if not signature_header.startswith('sha256='):
        logger.warning("Invalid signature format")
        return False
    
    hash_object = hmac.new(github_secret, msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    
    if not hmac.compare_digest(expected_signature, signature_header):
        logger.warning("Request signature does not match.")
        return False
    
    return True

def validate_webhook_payload(payload: Dict[str, Any]) -> bool:
    """Validate the structure of the webhook payload."""
    if not isinstance(payload, dict):
        return False
    
    # Check required fields
    if 'action' not in payload:
        return False
    
    if 'pull_request' not in payload:
        return False
    
    pr = payload['pull_request']
    if not isinstance(pr, dict):
        return False
    
    required_pr_fields = ['title', 'html_url', 'user']
    for field in required_pr_fields:
        if field not in pr:
            return False
    
    # Validate URL format
    pr_url = pr.get('html_url', '')
    if not pr_url.startswith('https://github.com/'):
        return False
    
    return True

# --- Slack Messaging ---
def send_slack_dm(user_id, message_blocks):
    """Sends a Direct Message to a Slack user."""
    try:
        slack_client.chat_postMessage(
            channel=user_id,
            blocks=message_blocks,
            text=f"You have a new GitHub PR notification."
        )
        logging.info(f"Sent notification to Slack user {user_id}")
    except SlackApiError as e:
        logging.error(f"Error sending Slack message to {user_id}: {e.response['error']}")

def create_pr_message_blocks(payload, summary, reason):
    """Creates formatted message blocks for a PR notification."""
    pr_title = payload['pull_request']['title']
    pr_url = payload['pull_request']['html_url']
    pr_author = payload['pull_request']['user']['login']
    repo_name = payload['repository']['full_name']

    return [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f":bell: {reason}",
                "emoji": True
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*<{pr_url}|{pr_title}>*\n*Repository:* {repo_name}\n*Author:* {pr_author}"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Summary:* {summary}"
            }
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "View PR on GitHub",
                        "emoji": True
                    },
                    "url": pr_url,
                    "action_id": "view_pr_button"
                }
            ]
        }
    ]

# --- Reminder Logic ---
def schedule_reminder(pr_url, user_id, pr_title):
    """Schedules a new reminder job."""
    job_id = f"reminder_{pr_url}_{user_id}"
    run_date = datetime.now() + timedelta(hours=REMINDER_DELAY_HOURS)
    
    # Remove any existing job with the same ID to avoid duplicates
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
        logging.info(f"Removed existing reminder job: {job_id}")

    scheduler.add_job(
        send_reminder,
        'date',
        run_date=run_date,
        args=[pr_url, user_id, pr_title],
        id=job_id
    )
    logging.info(f"Scheduled reminder for {pr_url} to user {user_id} at {run_date}")

def send_reminder(pr_url, user_id, pr_title):
    """The function executed by the scheduler to send a reminder."""
    logging.info(f"Sending reminder for {pr_url} to user {user_id}")
    message_blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": ":alarm_clock: Reminder: Action Needed",
                "emoji": True
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"This PR is still waiting for your review:\n*<{pr_url}|{pr_title}>*"
            }
        }
    ]
    send_slack_dm(user_id, message_blocks)
    
    # Schedule the next reminder
    job_id = f"reminder_{pr_url}_{user_id}"
    next_run_date = datetime.now() + timedelta(hours=REMINDER_INTERVAL_HOURS)
    scheduler.add_job(
        send_reminder,
        'date',
        run_date=next_run_date,
        args=[pr_url, user_id, pr_title],
        id=job_id,
        replace_existing=True
    )
    logging.info(f"Rescheduled next reminder for {job_id} at {next_run_date}")


def cancel_reminders(pr_url):
    """Cancels all reminders associated with a specific PR."""
    for job in scheduler.get_jobs():
        if job.id.startswith(f"reminder_{pr_url}_"):
            scheduler.remove_job(job.id)
            logging.info(f"Cancelled reminder job: {job.id}")


# --- Webhook Handler ---
@app.route('/github/webhook', methods=['POST'])
def github_webhook():
    client_ip = request.remote_addr
    
    # 1. Rate limiting
    if is_rate_limited(client_ip):
        logger.warning(f"Rate limit exceeded for {client_ip}")
        abort(429, 'Rate limit exceeded')
    
    # 2. Verify the signature
    signature = request.headers.get('X-Hub-Signature-256')
    if not verify_github_signature(request.data, signature):
        logger.warning(f"Invalid signature from {client_ip}")
        abort(400, 'Invalid signature.')

    # 3. Check the event type
    event_type = request.headers.get('X-GitHub-Event')
    if event_type != 'pull_request':
        logger.info(f"Unsupported event type: {event_type}")
        return 'Event not supported.', 200

    # 4. Validate and process the payload
    try:
        payload = request.json
        if not payload:
            logger.warning("Empty payload received")
            abort(400, 'Empty payload')
        
        if not validate_webhook_payload(payload):
            logger.warning("Invalid payload structure")
            abort(400, 'Invalid payload structure')
        
        handle_pull_request_event(payload)
        logger.info(f"Successfully processed webhook for action: {payload.get('action')}")
        
    except Exception as e:
        logger.error(f"Error processing webhook: {str(e)}")
        abort(500, 'Internal server error')
    
    return 'Event received.', 200

def handle_pull_request_event(payload):
    """Main logic to process PR events and notify users."""
    action = payload.get('action')
    pr = payload.get('pull_request', {})
    
    if not pr:
        return

    pr_author_github = pr.get('user', {}).get('login', '').lower()
    pr_url = pr.get('html_url')

    # If PR is closed or merged, cancel all associated reminders
    if action in ['closed', 'merged']:
        logging.info(f"PR {pr_url} was closed/merged. Cancelling reminders.")
        cancel_reminders(pr_url)
        return

    pr_title = pr.get('title')
    pr_body = pr.get('body', '')
    summary = gemini_service.summarize_pr(pr_title, pr_body)

    # --- Notify PR Author ---
    if action == 'opened':
        if pr_author_github in USER_MAPPING:
            slack_user_id = USER_MAPPING[pr_author_github]
            reason = "Your PR was opened"
            message = create_pr_message_blocks(payload, summary, reason)
            send_slack_dm(slack_user_id, message)
    
    # --- Notify Requested Reviewers ---
    if action == 'review_requested':
        requested_reviewer = payload.get('requested_reviewer', {}).get('login', '').lower()
        if requested_reviewer in USER_MAPPING:
            slack_user_id = USER_MAPPING[requested_reviewer]
            reason = "Your review is requested"
            message = create_pr_message_blocks(payload, summary, reason)
            send_slack_dm(slack_user_id, message)
            # Schedule a reminder for the reviewer
            schedule_reminder(pr_url, slack_user_id, pr_title)


if __name__ == '__main__':
    logger.info("Starting GitHub PR Notifier App...")
    
    # Get configuration from environment
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    if debug_mode:
        logger.warning("Running in debug mode - DO NOT USE IN PRODUCTION")
    
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
