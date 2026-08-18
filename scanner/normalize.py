"""Normalize raw scanner alerts into the neutral ``Finding`` schema.

Right now only ZAP is wired in, but keeping normalization in its own module
means adding testssl/nuclei later (Phase 2) is just another ``from_*``
function feeding the same ``Finding`` list. Deduplication happens here so the
AI layer never sees the same issue N times (ZAP emits one alert per URL/param).
"""

from __future__ import annotations

from typing import Any, Optional

from .models import Finding


def _to_int(value: Any) -> Optional[int]:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    # ZAP uses -1 for "not applicable"; treat that as absent.
    return n if n >= 0 else None


def from_zap_alert(alert: dict[str, Any]) -> Finding:
    """Map one ZAP alert dict to a Finding."""
    return Finding(
        source="zap",
        name=alert.get("alert") or alert.get("name") or "Unknown",
        risk=alert.get("risk") or "Informational",
        confidence=alert.get("confidence") or "Low",
        url=alert.get("url") or "",
        description=alert.get("description") or "",
        solution=alert.get("solution") or "",
        evidence=alert.get("evidence") or "",
        param=alert.get("param") or "",
        attack=alert.get("attack") or "",
        cwe_id=_to_int(alert.get("cweid")),
        wasc_id=_to_int(alert.get("wascid")),
        plugin_id=str(alert.get("pluginId")) if alert.get("pluginId") else None,
        reference=alert.get("reference") or "",
        raw=alert,
    )


def normalize_zap(alerts: list[dict[str, Any]]) -> list[Finding]:
    """Normalize + dedupe a batch of ZAP alerts."""
    seen: dict[tuple, Finding] = {}
    for alert in alerts:
        finding = from_zap_alert(alert)
        key = finding.dedupe_key()
        # First occurrence wins; ZAP orders by discovery, and the first URL is
        # a fine representative. Later sources could merge instead if needed.
        seen.setdefault(key, finding)
    return list(seen.values())
