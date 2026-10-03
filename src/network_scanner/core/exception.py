class NetworkScannerError(Exception):
    """Base exception for all network-scanner errors."""


class ScanPermissionError(NetworkScannerError):
    """Insufficient privileges to perform a raw-socket scan."""


class InvalidTargetError(NetworkScannerError):
    """Target network/IP range is malformed."""


class VendorLookupError(NetworkScannerError):
    """Vendor database is unavailable or not initialized."""
