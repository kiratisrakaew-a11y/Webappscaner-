"""Static ground-truth mappings: CWE / ZAP plugin -> OWASP Top 10 (2021) + WSTG.

Why this exists:
    The AI layer is good at reading evidence and writing remediation, but it
    should NOT be left to *guess* which OWASP category or CWE a finding belongs
    to — those are lookups, not judgement calls. We resolve them here from
    authoritative tables and pass the result into the prompt as ground truth,
    so the AI confirms/annotates rather than inventing identifiers.

Sources:
    - OWASP Top 10 2021 category->CWE lists (owasp.org/Top10)
    - OWASP Web Security Testing Guide (WSTG) v4.2 test IDs
    - ZAP alert pluginId -> CWE (from ZAP's own alert metadata)

The tables are intentionally a *useful subset*, not exhaustive. Anything not
matched falls back to ``UNKNOWN_CATEGORY`` and the finding is still reported.
"""

from __future__ import annotations

from typing import Optional

from .models import Finding


# ---------------------------------------------------------------------------
# OWASP Top 10 2021 categories (canonical display strings)
# ---------------------------------------------------------------------------
A01 = "A01:2021 - Broken Access Control"
A02 = "A02:2021 - Cryptographic Failures"
A03 = "A03:2021 - Injection"
A04 = "A04:2021 - Insecure Design"
A05 = "A05:2021 - Security Misconfiguration"
A06 = "A06:2021 - Vulnerable and Outdated Components"
A07 = "A07:2021 - Identification and Authentication Failures"
A08 = "A08:2021 - Software and Data Integrity Failures"
A09 = "A09:2021 - Security Logging and Monitoring Failures"
A10 = "A10:2021 - Server-Side Request Forgery (SSRF)"
UNKNOWN_CATEGORY = "Unmapped - needs manual triage"

# Coverage note per category for black-box (DAST) scanning. Surfaced in the
# report so nobody reads a clean scan as "fully covered".
BLACK_BOX_COVERAGE = {
    A01: "บางส่วน — access control ต้องมี multi-user login context จึงจะตรวจได้ครบ",
    A02: "ดี — DAST ตรวจ TLS/cipher/cookie flags ได้",
    A03: "ดี — จุดแข็งของ DAST (SQLi/XSS/command injection)",
    A04: "จำกัดมาก — insecure design ต้อง threat modeling ไม่ใช่ scanner",
    A05: "ดี — headers, dir listing, error leak ตรวจได้",
    A06: "บางส่วน — fingerprint version ได้ แต่ยืนยัน CVE ต้องข้อมูลเพิ่ม",
    A07: "บางส่วน — session/brute-force ได้ แต่ MFA/policy ตรวจยาก",
    A08: "จำกัด — SRI missing ตรวจได้ แต่ deserialization ยาก",
    A09: "แทบไม่ได้ — logging/monitoring มองจากภายนอกไม่เห็น",
    A10: "บางส่วน — ตรวจได้ถ้า input trigger server-side request",
    UNKNOWN_CATEGORY: "ต้องตรวจสอบด้วยผู้เชี่ยวชาญ",
}


# ---------------------------------------------------------------------------
# CWE -> OWASP 2021 category. Subset of the official mapping, focused on the
# CWEs that black-box scanners actually emit.
# ---------------------------------------------------------------------------
CWE_TO_OWASP: dict[int, str] = {
    # A01 Broken Access Control
    22: A01, 23: A01, 35: A01, 59: A01, 200: A01, 201: A01, 219: A01,
    264: A01, 275: A01, 276: A01, 284: A01, 285: A01, 352: A01, 419: A01,
    538: A01, 601: A01, 639: A01, 651: A01, 668: A01, 706: A01, 862: A01,
    863: A01, 913: A01, 922: A01, 1275: A01,
    # A02 Cryptographic Failures
    261: A02, 296: A02, 310: A02, 319: A02, 321: A02, 322: A02, 323: A02,
    324: A02, 325: A02, 326: A02, 327: A02, 328: A02, 329: A02, 330: A02,
    331: A02, 335: A02, 336: A02, 337: A02, 338: A02, 340: A02, 347: A02,
    523: A02, 720: A02, 757: A02, 759: A02, 760: A02, 780: A02, 818: A02,
    916: A02,
    # A03 Injection
    20: A03, 74: A03, 75: A03, 77: A03, 78: A03, 79: A03, 80: A03, 83: A03,
    87: A03, 88: A03, 89: A03, 90: A03, 91: A03, 93: A03, 94: A03, 95: A03,
    96: A03, 97: A03, 98: A03, 99: A03, 100: A03, 113: A03, 116: A03,
    138: A03, 184: A03, 470: A03, 471: A03, 564: A03, 610: A03, 643: A03,
    644: A03, 652: A03, 917: A03,
    # A04 Insecure Design
    73: A04, 183: A04, 209: A04, 213: A04, 235: A04, 256: A04, 257: A04,
    266: A04, 269: A04, 280: A04, 311: A04, 312: A04, 313: A04, 316: A04,
    419: A04, 430: A04, 434: A04, 444: A04, 451: A04, 472: A04, 501: A04,
    522: A04, 525: A04, 539: A04, 579: A04, 598: A04, 602: A04, 642: A04,
    646: A04, 650: A04, 653: A04, 656: A04, 657: A04, 799: A04, 807: A04,
    840: A04, 841: A04, 927: A04, 1021: A04, 1173: A04,
    # A05 Security Misconfiguration
    2: A05, 11: A05, 13: A05, 15: A05, 16: A05, 260: A05, 315: A05, 520: A05,
    526: A05, 537: A05, 541: A05, 547: A05, 611: A05, 614: A05, 693: A05,
    756: A05, 776: A05, 942: A05, 1004: A05, 1032: A05, 1174: A05,
    # A06 Vulnerable and Outdated Components
    937: A06, 1035: A06, 1104: A06,
    # A07 Identification and Authentication Failures
    255: A07, 259: A07, 287: A07, 288: A07, 290: A07, 294: A07, 295: A07,
    297: A07, 300: A07, 302: A07, 304: A07, 306: A07, 307: A07, 346: A07,
    384: A07, 521: A07, 613: A07, 620: A07, 640: A07, 798: A07, 940: A07,
    1216: A07,
    # A08 Software and Data Integrity Failures
    345: A08, 353: A08, 426: A08, 494: A08, 502: A08, 565: A08, 784: A08,
    829: A08, 830: A08, 915: A08,
    # A09 Security Logging and Monitoring Failures
    117: A09, 223: A09, 532: A09, 778: A09,
    # A10 Server-Side Request Forgery
    918: A10,
}


# ---------------------------------------------------------------------------
# OWASP category -> a representative WSTG test id (default when we can't be
# more specific from the finding name).
# ---------------------------------------------------------------------------
OWASP_TO_WSTG: dict[str, str] = {
    A01: "WSTG-ATHZ-02",   # Testing for Bypassing Authorization Schema
    A02: "WSTG-CRYP-01",   # Testing for Weak Transport Layer Security
    A03: "WSTG-INPV-01",   # Testing for Injection (input validation family)
    A04: "WSTG-BUSL-01",   # Business logic / design
    A05: "WSTG-CONF-02",   # Testing Application Platform Configuration
    A06: "WSTG-CONF-01",   # Fingerprinting / known component versions
    A07: "WSTG-ATHN-01",   # Authentication testing family
    A08: "WSTG-CLNT-01",   # Client-side / integrity
    A09: "WSTG-CONF-11",   # Logging / error handling review
    A10: "WSTG-INPV-19",   # Testing for Server-Side Request Forgery
    UNKNOWN_CATEGORY: "WSTG-INFO-01",
}

# More specific WSTG ids keyed by substrings in the finding name (checked
# before the category default). Keeps A03 from always resolving to INPV-01.
NAME_TO_WSTG: list[tuple[str, str]] = [
    ("sql injection", "WSTG-INPV-05"),
    ("cross site scripting", "WSTG-INPV-01"),
    ("cross-site scripting", "WSTG-INPV-01"),
    ("reflected xss", "WSTG-INPV-01"),
    ("persistent xss", "WSTG-INPV-02"),
    ("command injection", "WSTG-INPV-12"),
    ("code injection", "WSTG-INPV-11"),
    ("ldap injection", "WSTG-INPV-06"),
    ("xpath injection", "WSTG-INPV-09"),
    ("xml external entity", "WSTG-INPV-07"),
    ("xxe", "WSTG-INPV-07"),
    ("path traversal", "WSTG-ATHZ-01"),
    ("directory browsing", "WSTG-CONF-04"),
    ("directory listing", "WSTG-CONF-04"),
    ("cross-domain misconfiguration", "WSTG-CONF-07"),
    ("cookie", "WSTG-SESS-02"),
    ("session", "WSTG-SESS-01"),
    ("csrf", "WSTG-SESS-05"),
    ("cross-site request forgery", "WSTG-SESS-05"),
    ("open redirect", "WSTG-CLNT-04"),
    ("content security policy", "WSTG-CONF-12"),
    ("strict-transport-security", "WSTG-CONF-07"),
    ("tls", "WSTG-CRYP-01"),
    ("ssl", "WSTG-CRYP-01"),
    ("server-side request forgery", "WSTG-INPV-19"),
    ("ssrf", "WSTG-INPV-19"),
    ("error message", "WSTG-ERRH-01"),
    ("stack trace", "WSTG-ERRH-02"),
]


# ---------------------------------------------------------------------------
# ZAP pluginId -> CWE, for the alerts where ZAP omits/underspecifies the CWE.
# Only needed as a backstop; ZAP usually reports cweid itself.
# ---------------------------------------------------------------------------
ZAP_PLUGIN_TO_CWE: dict[str, int] = {
    "40018": 89,    # SQL Injection
    "40012": 79,    # Reflected XSS
    "40014": 79,    # Persistent XSS
    "40016": 79,    # Persistent XSS (prime)
    "40017": 79,    # Persistent XSS (spider)
    "90019": 94,    # Server-side code injection
    "90020": 78,    # Remote OS command injection
    "6":     22,    # Path traversal
    "40028": 22,    # LDAP injection (family)
    "0":     200,   # Directory browsing / info
    "10202": 352,   # Absence of anti-CSRF tokens
    "10038": 693,   # CSP header not set (mapped below via fallback)
    "10035": 16,    # Strict-Transport-Security header
    "10021": 16,    # X-Content-Type-Options missing
    "10020": 1021,  # Anti-clickjacking / X-Frame-Options
    "10054": 1004,  # Cookie without HttpOnly
    "10011": 614,   # Cookie without Secure flag
    "90022": 918,   # Application error / SSRF family
    "40003": 113,   # CRLF injection / HTTP response splitting
    "10098": 200,   # Cross-domain misconfiguration
}


def resolve_owasp(finding: Finding) -> tuple[str, str, Optional[int]]:
    """Return (owasp_category, wstg_id, cwe_id) for a finding.

    Resolution order for CWE: the finding's own cwe_id, then a plugin-id
    backstop. The OWASP category is derived from the resolved CWE; the WSTG id
    prefers a name-specific match and falls back to the category default.
    """
    cwe = finding.cwe_id
    if cwe is None and finding.plugin_id:
        cwe = ZAP_PLUGIN_TO_CWE.get(str(finding.plugin_id))

    category = CWE_TO_OWASP.get(cwe, UNKNOWN_CATEGORY) if cwe else UNKNOWN_CATEGORY

    wstg = OWASP_TO_WSTG.get(category, OWASP_TO_WSTG[UNKNOWN_CATEGORY])
    name_l = (finding.name or "").lower()
    for needle, wstg_id in NAME_TO_WSTG:
        if needle in name_l:
            wstg = wstg_id
            break

    return category, wstg, cwe


def coverage_note(category: str) -> str:
    """Black-box coverage caveat for a given OWASP category."""
    return BLACK_BOX_COVERAGE.get(category, "")
