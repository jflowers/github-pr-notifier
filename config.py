# config.py

# Map GitHub usernames (lowercase) to Slack User IDs.
# Find Slack User ID by clicking a user's profile -> ... -> "Copy member ID"
USER_MAPPING = {
    # "github-username": "SLACK_USER_ID",
    "octocat": "U024BE7LH",
    "monalisa": "U012ABC3DE",
    "another-developer": "U987ZYX6WV"
}

# Reminder settings
REMINDER_DELAY_HOURS = 24 # Send first reminder after 24 hours
REMINDER_INTERVAL_HOURS = 48 # Send subsequent reminders every 48 hours