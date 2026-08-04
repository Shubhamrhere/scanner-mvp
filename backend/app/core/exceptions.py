"""
Custom exception classes for the application.
Maps domain errors to appropriate HTTP responses.
"""

from typing import Any, Dict, Optional


class AppException(Exception):
    """Base application exception."""

    def __init__(
        self,
        message: str,
        status_code: int = 500,
        detail: Optional[Dict[str, Any]] = None,
    ):
        self.message = message
        self.status_code = status_code
        self.detail = detail or {}
        super().__init__(self.message)


class NotFoundError(AppException):
    """Resource not found."""

    def __init__(self, resource: str, identifier: str):
        super().__init__(
            message=f"{resource} not found: {identifier}",
            status_code=404,
            detail={"resource": resource, "identifier": identifier},
        )


class ConflictError(AppException):
    """Resource already exists or conflicts with existing state."""

    def __init__(self, message: str):
        super().__init__(message=message, status_code=409)


class ForbiddenError(AppException):
    """Access denied due to insufficient permissions."""

    def __init__(self, message: str = "Access denied"):
        super().__init__(message=message, status_code=403)


class ValidationError(AppException):
    """Business logic validation failure."""

    def __init__(self, message: str, errors: Optional[Dict[str, Any]] = None):
        super().__init__(message=message, status_code=422, detail=errors or {})


class LockAcquisitionError(AppException):
    """Failed to acquire a distributed lock for a target."""

    def __init__(self, asset_id: str):
        super().__init__(
            message=f"Could not acquire lock for asset: {asset_id}",
            status_code=409,
            detail={"asset_id": asset_id},
        )


class ScannerError(AppException):
    """Scanner tool execution failure."""

    def __init__(self, tool: str, message: str):
        super().__init__(
            message=f"Scanner error [{tool}]: {message}",
            status_code=500,
            detail={"tool": tool},
        )


class StorageError(AppException):
    """Object storage (MinIO/S3) operation failure."""

    def __init__(self, operation: str, message: str):
        super().__init__(
            message=f"Storage error [{operation}]: {message}",
            status_code=500,
            detail={"operation": operation},
        )
