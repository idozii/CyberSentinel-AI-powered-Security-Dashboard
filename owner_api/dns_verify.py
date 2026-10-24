"""Bounded DNS TXT resolution; no HTTP requests or arbitrary destination URLs."""
from __future__ import annotations

import dns.exception
import dns.resolver


class LookupUnavailable(Exception):
    pass


def lookup_txt(name: str) -> list[str]:
    if not name.startswith("_cybersentinel-verify.") or len(name) > 255:
        raise LookupUnavailable("DNS verification record name is invalid")
    try:
        answer = dns.resolver.resolve(name, "TXT", lifetime=3.0, search=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as exc:
        raise LookupUnavailable("DNS resolver temporarily unavailable") from exc
    values = []
    for rdata in answer:
        try:
            value = b"".join(rdata.strings).decode("ascii", errors="strict")
        except (AttributeError, UnicodeDecodeError, TypeError):
            continue
        if len(value) <= 256:
            values.append(value)
        if len(values) >= 30:
            break
    return values
