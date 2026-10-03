from unittest.mock import patch

from mac_vendor_lookup import VendorNotFoundError

from network_scanner.utils import get_vendor
from network_scanner.utils.mac_vendor import UNKNOWN_VENDOR


def test_get_vendor_known():
    with patch("network_scanner.utils.mac_vendor.lookup.lookup", return_value="Apple, Inc."):
        assert get_vendor("00:1B:63:84:45:E6") == "Apple, Inc."


def test_get_vendor_not_found_in_db():
    with patch(
        "network_scanner.utils.mac_vendor.lookup.lookup",
        side_effect=VendorNotFoundError("ZZ:ZZ:ZZ:00:00:00"),
    ):
        assert get_vendor("ZZ:ZZ:ZZ:00:00:00") == UNKNOWN_VENDOR


def test_get_vendor_invalid_mac_format():
    with patch(
        "network_scanner.utils.mac_vendor.lookup.lookup",
        side_effect=ValueError("invalid literal for hex"),
    ):
        assert get_vendor("ZZ:ZZ:ZZ:00:00:00") == UNKNOWN_VENDOR


def test_get_vendor_empty_mac():
    assert get_vendor("") == UNKNOWN_VENDOR
    assert get_vendor(None) == UNKNOWN_VENDOR
