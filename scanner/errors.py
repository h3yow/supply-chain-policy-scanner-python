"""Error types with distinguishable error codes."""
from __future__ import annotations


class ScannerError(Exception):
    """Base error carrying a machine-readable code and HTTP status."""

    code: str = "internal_error"
    status_code: int = 500

    def __init__(self, message: str = "", *, details: dict | None = None) -> None:
        super().__init__(message or self.code)
        self.message = message or self.code
        self.details = details or {}


class AuthenticationError(ScannerError):
    code = "authentication_required"
    status_code = 401


class PermissionDeniedError(ScannerError):
    code = "permission_denied"
    status_code = 403


class PolicyNotFoundError(ScannerError):
    code = "policy_not_found"
    status_code = 404


class PolicyVersionNotFoundError(ScannerError):
    code = "policy_version_not_found"
    status_code = 404


class InvalidPolicyError(ScannerError):
    code = "invalid_policy"
    status_code = 422


class UnsupportedFormatError(ScannerError):
    code = "unsupported_format"
    status_code = 415


class ManifestParseError(ScannerError):
    """Whole-document parse failure (syntactically unreadable)."""

    code = "manifest_unparseable"
    status_code = 422


class ManifestRejectedError(ScannerError):
    """Document parsed but contains rejected entries (never silently skipped)."""

    code = "manifest_rejected"
    status_code = 422


class ConcurrentScanError(ScannerError):
    code = "concurrent_scan_failed"
    status_code = 500
