from mac_vendor_lookup import MacLookup

lookup = MacLookup()
lookup.async_update_vendors = False

def get_vendor(mac: str) -> str:
    """Determines the device manufacturer by MAC address"""
    if not mac:
        return "Unknown"
    try:
        return lookup.lookup(mac)
    except Exception:
        return "Unknown Vendor"

