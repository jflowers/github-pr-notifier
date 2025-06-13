# app.py
import os
import hmac
import hashlib
import json
import logging
from datetime import datetime, timedelta

from flask import Flask, request, abort
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler

from config import USER_MAPPING, REMINDER_DELAY_HOURS, REMINDER_INTERVAL_HOURS
import gemini_service

# --- Initialization ---
logging.basicConfig(level=logging.INFO)
load_dotenv()

app = Flask(__name__)

# Slack client
slack_token = os.environ["SLACK_BOT_TOKEN"]
slack_client = WebClient(token=slack_token)

# GitHub webhook secret
github_secret = os.environ["GITHUB_WEBHOOK_SECRET"].encode('utf-8')

# Scheduler for reminders
scheduler = BackgroundScheduler()
scheduler.start()


# --- Security ---
def verify_github_signature(payload_body, signature_header):
    """Verify that the payload was sent from GitHub by validating the signature."""
    if not signature_header:
        logging.warning("No X-Hub-Signature-256 header on request.")
        return False
    hash_object = hmac.new(github_secret, msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    if not hmac.compare_digest(expected_signature, signature_header):
        logging.warning("Request signature does not match.")
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
    # 1. Verify the signature
    signature = request.headers.get('X-Hub-Signature-256')
    if not verify_github_signature(request.data, signature):
        abort(400, 'Invalid signature.')

    # 2. Check the event type
    event_type = request.headers.get('X-GitHub-Event')
    if event_type != 'pull_request':
        return 'Event not supported.', 200

    # 3. Process the payload
    payload = request.json
    handle_pull_request_event(payload)
    
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
    logging.info("Starting GitHub PR Notifier App...")
    # Port must match the ngrok command
    app.run(port=5000, debug=True)