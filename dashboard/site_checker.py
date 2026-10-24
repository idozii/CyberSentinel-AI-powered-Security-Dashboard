"""CyberSentinel Step 9: tightly bounded, passive HTTPS header check.

This is NOT a vulnerability scan and does not authorize testing external assets.
Only one HEAD / request to a public HTTPS/443 origin; no redirects or login.
SSRF controls: reject unsafe names and IP literals, validate ALL DNS answers,
then connect DIRECTLY to one approved IPv4 address with hostname-bound TLS.
For public multi-user hosting, add independent global quotas and egress firewalling.
"""
from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
from urllib.parse import urlsplit

TIMEOUT_SECONDS = 4.0
WEIGHTS = {
    "hsts": 20,
    "csp": 25,
    "nosniff": 15,
    "referrer_policy": 10,
    "permissions_policy": 10,
    "clickjacking": 20,
}
CHECK_LABELS = {
    "hsts": "HSTS ≥ 1 year",
    "csp": "Content-Security-Policy header present",
    "nosniff": "X-Content-Type-Options: nosniff",
    "referrer_policy": "Restrictive Referrer-Policy",
    "permissions_policy": "Permissions-Policy header present",
    "clickjacking": "frame-ancestors or X-Frame-Options",
}


class SiteCheckError(ValueError):
    """A website cannot be scanned under the passive public-check policy."""


def normalize_domain(value: str) -> str:
    """Accept only a normal ASCII FQDN or https://FQDN[/] with no extra URL parts."""
    if not isinstance(value, str) or not value or len(value) > 280:
        raise SiteCheckError("Enter a valid public hostname, e.g. www.example.com")
    if any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise SiteCheckError("Spaces, Unicode and control characters are not accepted; use ASCII/Punycode")
    if "\\" in value or "%" in value:
        raise SiteCheckError("Encoded/escaped URL forms are not supported")
    if "://" not in value:
        value = "https://" + value
    try:
        url = urlsplit(value)
        host = url.hostname
        port = url.port
    except ValueError as exc:
        raise SiteCheckError("Invalid URL or port") from exc
    if (url.scheme != "https" or not host or url.username is not None or
            url.password is not None or port is not None or url.query or
            url.fragment or url.path not in ("", "/")):
        raise SiteCheckError("Only HTTPS hostnames on default port 443 are supported (no path/query/credentials)")
    host = host.lower()
    if len(host) > 253 or host.endswith(".") or host.startswith("."):
        raise SiteCheckError("Invalid hostname format")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise SiteCheckError("IP literals are not supported; enter a public domain name")
    labels = host.split(".")
    if len(labels) < 2 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
        raise SiteCheckError("Enter a valid fully-qualified domain name")
    if not re.fullmatch(r"[a-z]{2,63}|xn--[a-z0-9-]{2,59}", labels[-1]):
        raise SiteCheckError("Invalid public domain suffix")
    if labels[-1] in {"local", "internal", "localhost", "invalid", "test", "example"}:
        raise SiteCheckError("Reserved/internal domains are not supported")
    return host


def resolve_public_ipv4(hostname: str) -> str:
    """Review *every* DNS A/AAAA answer; connect to a checked IPv4 only.

    Deliberate MVP restriction: IPv6-only hosts are reported as unsupported.
    Reject mixed public/private answers, even when a public A record exists.
    """
    try:
        answers = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError) as exc:
        raise SiteCheckError("Hostname cannot be resolved") from exc
    if not answers:
        raise SiteCheckError("No DNS addresses returned")
    ips = set()
    for family, _type, _proto, _canonical, sockaddr in answers:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise SiteCheckError("Unsupported DNS address family")
        try:
            address = ipaddress.ip_address(sockaddr[0])
        except ValueError as exc:
            raise SiteCheckError("Invalid DNS address") from exc
        if not address.is_global:
            raise SiteCheckError("Destination resolves to a non-public network; request blocked")
        # Reject IPv4-mapped/translation or special IPv6 types as a conservative policy.
        if isinstance(address, ipaddress.IPv6Address) and (
            address.ipv4_mapped is not None or address.sixtofour is not None or address.teredo is not None
        ):
            raise SiteCheckError("Special-use IPv6 DNS answer is not allowed")
        ips.add(address)
    ipv4s = sorted(str(x) for x in ips if isinstance(x, ipaddress.IPv4Address))
    if not ipv4s:
        raise SiteCheckError("This MVP requires a public IPv4 address; IPv6-only sites are unsupported")
    return ipv4s[0]


def fetch_headers(hostname: str, approved_ip: str) -> tuple[int, dict[str, str]]:
    """Send exactly one HEAD /; connect to approved IP and verify TLS for hostname.

    Avoid a second DNS query (rebinding risk); don't use automatic redirects.
    """
    address = ipaddress.ip_address(approved_ip)
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
        raise SiteCheckError("Unsafe network destination rejected")
    context = ssl.create_default_context()
    try:
        with socket.create_connection((approved_ip, 443), timeout=TIMEOUT_SECONDS) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as tls:
                tls.settimeout(TIMEOUT_SECONDS)
                # SiteCheckError limits host to valid DNS label chars => no CRLF injection.
                request_line = ("HEAD / HTTP/1.1\r\nHost: " + hostname +
                                "\r\nUser-Agent: CyberSentinel-PostureCheck/0.1\r\n"
                                "Accept: */*\r\nConnection: close\r\n\r\n")
                tls.sendall(request_line.encode("ascii"))
                response = http.client.HTTPResponse(tls, method="HEAD")
                response.begin()  # stdlib places limits on response header count/size
                status = response.status
                headers = {k.lower(): v[:350] for k, v in response.getheaders()}
                response.close()
                return status, headers
    except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as exc:
        raise SiteCheckError("HTTPS/TLS connection failed or timed out; no score assigned") from exc


def _hsts_one_year(value: str) -> bool:
    matches = re.findall(r"(?:^|;)\s*max-age\s*=\s*(\d+)(?:\s*;|\s*$)", value, flags=re.I)
    return bool(matches and int(matches[0]) >= 31536000)


def evaluate_headers(headers: dict[str, str]) -> dict:
    headers = {key.lower(): value for key, value in headers.items()}
    csp = headers.get("content-security-policy", "")
    xfo = headers.get("x-frame-options", "").strip().upper()
    ref = headers.get("referrer-policy", "").strip().lower()
    checks = {
        "hsts": _hsts_one_year(headers.get("strict-transport-security", "")),
        "csp": bool(csp.strip()),
        "nosniff": headers.get("x-content-type-options", "").strip().lower() == "nosniff",
        "referrer_policy": ref in {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"},
        "permissions_policy": bool(headers.get("permissions-policy", "").strip()),
        "clickjacking": ("frame-ancestors" in csp.lower()) or xfo in {"DENY", "SAMEORIGIN"},
    }
    score = sum(WEIGHTS[name] for name, passed in checks.items() if passed)
    return {
        "score": score,
        "max_score": sum(WEIGHTS.values()),
        "checks": [{"id": key, "label": CHECK_LABELS[key], "passed": checks[key], "points": WEIGHTS[key]}
                   for key in WEIGHTS],
        "disclaimer": "Header-configuration completeness, NOT a security guarantee, vulnerability scan or malware verdict.",
    }


def check_website(target: str) -> dict:
    hostname = normalize_domain(target)
    approved_ip = resolve_public_ipv4(hostname)
    code, headers = fetch_headers(hostname, approved_ip)
    # Not follow redirect, never reinterpret results for a different origin.
    result = {"hostname": hostname, "https_certificate_verified": True,
              "http_status": code, "checked_path": "/", "method": "HEAD"}
    if code in range(300, 400):
        result.update({"status": "not_scored", "message": "Redirect received; destination was not followed or checked."})
    elif code in (405, 501):
        result.update({"status": "not_scored", "message": "Origin does not support HEAD; no assessment performed."})
    elif not 200 <= code < 300:
        result.update({"status": "not_scored", "message": "Non-success HTTP response; no assessment performed."})
    else:
        result.update({"status": "evaluated", **evaluate_headers(headers)})
    return result
