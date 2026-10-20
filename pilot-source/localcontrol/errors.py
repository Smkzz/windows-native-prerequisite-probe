class ControlError(Exception):
    """A stable public error; never include secrets from an underlying exception.

    Optional `details` carries bounded, non-secret machine-readable context
    (for example the valid project names for a PROJECT_REQUIRED error).
    """
    def __init__(self, code: str, message: str, details: dict | None = None):
        super().__init__(message)
        self.code = code
        self.details = details


def require(condition: bool, code: str, message: str, details: dict | None = None) -> None:
    if not condition:
        raise ControlError(code, message, details)
