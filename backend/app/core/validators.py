import socket
import ipaddress
from urllib.parse import urlparse
from fastapi import HTTPException

_BLOCKED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("::ffff:0:0/96"),
]

def validate_no_ssrf(url: str):
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL: could not extract hostname")

    try:
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Could not resolve hostname")

    for blocked in _BLOCKED_RANGES:
        if ip_obj in blocked:
            raise HTTPException(
                status_code=400,
                detail="Scanning internal or private network addresses is not allowed"
            )
