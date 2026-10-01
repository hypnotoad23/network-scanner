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
    except VendorNotFoundError:
        return UNKNOWN_VENDOR
    except FileNotFoundError:
        return UNKNOWN_VENDOR
