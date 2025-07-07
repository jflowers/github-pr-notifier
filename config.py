# config.py

# SECURITY NOTE: Remove all sample data before production deployment
# Map GitHub usernames (lowercase) to Slack User IDs.
# Find Slack User ID by clicking a user's profile -> ... -> "Copy member ID"
USER_MAPPING = {
    # "github-username": "SLACK_USER_ID",
    # TODO: Replace with actual user mappings before deployment
    # Example:
    # "your-github-username": "U024BE7LH",
}

# Reminder settings
REMINDER_DELAY_HOURS = 24  # Send first reminder after 24 hours
REMINDER_INTERVAL_HOURS = 48  # Send subsequent reminders every 48 hours

# Validate configuration
if not USER_MAPPING:
    import logging
    logging.warning("USER_MAPPING is empty - no notifications will be sent")
