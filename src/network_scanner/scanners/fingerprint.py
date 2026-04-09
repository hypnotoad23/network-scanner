from typing import Optional

def get_os_guess(ttl: Optional[int], window_size: Optional[int] = None) -> str:
    """
    Simple determination of the OS based on the initial TTL result
    """
    if ttl is None:
        return "Unknown"

    #We bring TTL to the initial value (considering that it decreases along the way)
    if ttl >128:
        initial_ttl = 255
    elif ttl > 64:
        initial_ttl = 128
    else:
        initial_ttl = 64
    
    
    #Basic definition by initial TTL
    if initial_ttl == 64:
        os_name = "Linux / Android / macOS"
    elif initial_ttl == 128:
        os_name = "Windows"
    elif initial_ttl == 255:
        os_name = "Network Device (Cisco, etc.)"
    else:
        os_name = "Unknown"

    if os_name == "Linux / Android / macOS" and window_size and window_size > 60000:
        os_name = "macOS (likely)"

    return os_name

