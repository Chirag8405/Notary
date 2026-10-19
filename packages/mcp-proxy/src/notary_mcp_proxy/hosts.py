"""Which host names count as this machine."""

import ipaddress


def is_loopback_host(host: str) -> bool:
    """`localhost` or a loopback address (127.0.0.0/8, ::1). Names are not resolved."""
    name = host.strip("[]").lower().rstrip(".")
    if name == "localhost":
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False
