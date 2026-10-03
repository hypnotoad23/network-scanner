from mac_vendor_lookup import MacLookup, VendorNotFoundError

UNKNOWN_VENDOR = "Unknown Vendor"

lookup = MacLookup()
lookup.async_update_vendors = False


def get_vendor(mac: str) -> str:
# Определение производителя устройства по MAC-адресу
    if not mac:
        return UNKNOWN_VENDOR

    try:
        return lookup.lookup(mac)
    except (VendorNotFoundError, FileNotFoundError, ValueError):
        return UNKNOWN_VENDOR
