"""
ROGUEPULSE Configuration
Central platform settings.
"""

APP_NAME = "ROGUEPULSE"
APP_VERSION = "1.0.0"

APP_DESCRIPTION = (
    "Automated Cybersecurity Learning and "
    "Local Laboratory Analysis Platform"
)

# Approved testing environments
ALLOWED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1"
}

# Connection settings
REQUEST_TIMEOUT = 5
FOLLOW_REDIRECTS = False

# Application settings
DEBUG_MODE = True
LOG_LEVEL = "INFO"

# Directory settings
REPORT_DIRECTORY = "reports"