"""Offline tests for the non-network parts of the pipeline.

Run: python -m pytest tests/  (or: python tests/test_pipeline.py)
These cover the auth gate, normalization/dedupe, and static OWASP mapping —
everything that does not need a live ZAP daemon or an API key.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import auth_gate, normalize, mappings, ai_assessor, report  # noqa: E402


def test_auth_gate_allows_subdomains_and_denies_others():
    allow = auth_gate.load_allowlist(["example.com", "localhost"])
    assert auth_gate.authorize("http://app.example.com/x", allow)
    assert auth_gate.authorize("http://localhost:3000", allow)
    for bad in ["http://evil.com", "ftp://example.com", "notaurl"]:
        try:
            auth_gate.authorize(bad, allow)
            assert False, f"should have denied {bad}"
        except auth_gate.AuthorizationError:
            pass


def test_empty_allowlist_fails_closed():
    try:
        auth_gate.authorize("http://localhost", [])
        assert False, "empty allowlist must deny"
    except auth_gate.AuthorizationError:
        pass


def test_normalize_dedupes():
    alert = {"alert": "SQL Injection", "risk": "High", "confidence": "Medium",
             "url": "http://t/a", "param": "q", "cweid": "89", "pluginId": "40018"}
    findings = normalize.normalize_zap([alert, dict(alert, url="http://t/b")])
    assert len(findings) == 1  # same plugin+param collapses


def test_static_mapping_resolves_owasp():
    cases = {89: mappings.A03, 79: mappings.A03, 319: mappings.A02,
             1004: mappings.A05, 693: mappings.A05, 918: mappings.A10}
    for cwe, expected in cases.items():
        f = normalize.from_zap_alert({"alert": "x", "cweid": str(cwe), "url": "http://t"})
        cat, wstg, resolved = mappings.resolve_owasp(f)
        assert cat == expected, f"CWE-{cwe} -> {cat}, expected {expected}"
        assert wstg  # always some WSTG id
        assert resolved == cwe


def test_static_assessment_and_report_render():
    alerts = [{"alert": "SQL Injection", "risk": "High", "confidence": "Medium",
               "url": "http://t/x", "param": "q", "cweid": "89", "pluginId": "40018",
               "evidence": "SQL syntax error"}]
    findings = normalize.normalize_zap(alerts)
    assessed = ai_assessor.assess(findings, use_ai=False)
    assert assessed and assessed[0].assessment.assessed_by == "static-mapping"
    html = report.build_html("http://t", assessed)
    assert "Web Security Assessment Report" in html
    assert "A03:2021 - Injection" in html


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} tests passed")
