import pytest
from network_scanner.utils import get_vendor

def test_get_vendor_known():
    assert "Apple" in get_vendor("00:1B:63:84:45:E6")

def test_get_vendor_unknown():
    assert get_vendor("ZZ:ZZ:ZZ:00:00:00") == "Unknown Vendor"
