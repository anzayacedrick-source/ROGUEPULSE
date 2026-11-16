from config import APP_NAME, APP_VERSION
from core.scope_guard import ScopeGuard


class SecurityEngine:
    """Central coordination engine for ROGUEPULSE."""

    def __init__(self):
        self.name = APP_NAME
        self.version = APP_VERSION
        self.scope_guard = ScopeGuard()
        self.status = "INITIALIZED"

    def validate_target(self, target):
        return self.scope_guard.validate_target(target)

    def get_information(self):
        return {
            "name": self.name,
            "version": self.version,
            "engine_status": self.status,
            "testing_scope": "LOCAL LABORATORIES ONLY"
        }

    def get_status(self):
        return self.status

    def shutdown(self):
        self.status = "STOPPED"
        return self.status