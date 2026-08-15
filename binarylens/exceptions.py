"""Custom exceptions used throughout BinaryLens.

All of these are caught at the CLI boundary and turned into clean,
user-facing error messages instead of raw Python tracebacks.
"""


class BinaryLensError(Exception):
    """Base class for all BinaryLens errors."""


class FileNotFoundErrorBL(BinaryLensError):
    """Raised when the target file does not exist."""


class PermissionDeniedError(BinaryLensError):
    """Raised when the target file cannot be read due to permissions."""


class UnsupportedFormatError(BinaryLensError):
    """Raised when the file is not a recognized/supported binary format."""


class CorruptedBinaryError(BinaryLensError):
    """Raised when the file appears to be a supported format but is malformed."""


class EmptyFileError(BinaryLensError):
    """Raised when the target file has zero bytes."""
