"""Authorization gate — refuse to scan targets we have no permission for.

Active scanning sends real attack payloads; pointing it at a host you don't
own is illegal in most jurisdictions. This gate enforces an allowlist of hosts
BEFORE any traffic is sent. In Phase 0 the allowlist is a simple env/CLI list;
Phase 3 replaces it with real ownership verification (DNS TXT / meta tag).

The allowlist matches on hostname (and optional port), never on path, and an
entry matches its subdomains too (``example.com`` allows ``app.example.com``).
"""

from __future__ import annotations

import os
from urllib.parse import urlparse


class AuthorizationError(RuntimeError):
    """Raised when a target is not covered by the allowlist."""


def load_allowlist(explicit: list[str] | None = None) -> list[str]:
    """Build the allowlist from an explicit list and/or SCAN_ALLOWLIST env."""
    entries: list[str] = []
    if explicit:
        entries.extend(explicit)
    env = os.environ.get("SCAN_ALLOWLIST", "")
    entries.extend(part.strip() for part in env.split(",") if part.strip())
    # Normalize to lowercase hostnames (strip any scheme a user pasted in).
    normalized = []
    for e in entries:
        e = e.lower()
        if "://" in e:
            e = urlparse(e).netloc or e
        normalized.append(e)
    return normalized


def _host_matches(host: str, entry: str) -> bool:
    """True if host equals entry or is a subdomain of it (port-aware)."""
    if host == entry:
        return True
    # entry without port also allows any port on the same host
    host_noport = host.split(":", 1)[0]
    entry_noport = entry.split(":", 1)[0]
    if host_noport == entry_noport:
        return True
    return host_noport.endswith("." + entry_noport)


def authorize(target: str, allowlist: list[str]) -> str:
    """Return the validated target URL, or raise AuthorizationError.

    Requires an http(s) URL with a host, and that host present in the
    allowlist. An empty allowlist denies everything by design (fail-closed).
    """
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        raise AuthorizationError(
            f"target must be an http(s) URL, got: {target!r}"
        )
    host = (parsed.netloc or "").lower()
    if not host:
        raise AuthorizationError(f"could not parse host from target: {target!r}")

    if not allowlist:
        raise AuthorizationError(
            "allowlist is empty — refusing to scan. "
            "Set SCAN_ALLOWLIST or pass --allow <host>."
        )

    if any(_host_matches(host, entry) for entry in allowlist):
        return target

    raise AuthorizationError(
        f"host {host!r} is not in the authorized allowlist {allowlist}. "
        "Only scan systems you own or have written permission to test."
    )
