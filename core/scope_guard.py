from urllib.parse import urlparse

from config import ALLOWED_HOSTS


class ScopeGuard:
    """Controls which targets ROGUEPULSE may analyse."""

    def validate_target(self, target):
        if not isinstance(target, str) or not target.strip():
            return False

        try:
            parsed = urlparse(target.strip())

            if parsed.scheme not in ("http", "https"):
                return False

            if parsed.hostname not in ALLOWED_HOSTS:
                return False

            if parsed.username or parsed.password:
                return False

            if parsed.port is not None and not (
                1 <= parsed.port <= 65535
            ):
                return False

            return True

        except ValueError:
            return False

    def explain_rejection(self):
        return (
            "Target rejected. ROGUEPULSE only permits "
            "localhost and loopback laboratory targets."
        )