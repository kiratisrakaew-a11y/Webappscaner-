"""Shared data structures used across the scan pipeline.

The pipeline flows:
    URL -> ZAP -> Finding (normalized) -> Assessment (AI) -> Report

``Finding`` is the neutral schema every scan source (ZAP, and later
testssl/nuclei) is normalized into. ``Assessment`` is what the AI layer
attaches on top of a Finding. Keeping them as plain dataclasses makes the
JSON serialization in ``report.py`` trivial and keeps the modules decoupled.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


# Risk / confidence use a fixed vocabulary so the report and any downstream
# sorting stay stable regardless of which source produced the finding.
RISK_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}


@dataclass
class Finding:
    """A single normalized vulnerability finding (pre-AI)."""

    source: str                      # "zap", "testssl", "nuclei", ...
    name: str                        # human-readable alert name
    risk: str                        # Critical/High/Medium/Low/Informational
    confidence: str                  # High/Medium/Low (scanner's own confidence)
    url: str                         # affected URL
    description: str = ""
    solution: str = ""               # scanner-suggested fix (raw)
    evidence: str = ""               # matched string / proof from the scanner
    param: str = ""                  # affected parameter, if any
    attack: str = ""                 # payload the scanner sent, if any
    cwe_id: Optional[int] = None     # CWE reported by the scanner (may be None)
    wasc_id: Optional[int] = None
    plugin_id: Optional[str] = None  # ZAP pluginId — key for static mapping
    reference: str = ""              # reference URLs from the scanner
    raw: dict[str, Any] = field(default_factory=dict)  # untouched source record

    def dedupe_key(self) -> tuple:
        """Group identical issues that ZAP reports once per URL/param."""
        return (self.source, self.plugin_id or self.name, self.name, self.param)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("raw", None)  # keep the exported JSON readable; raw stays in memory
        return d


@dataclass
class Assessment:
    """AI (or static-fallback) assessment layered on top of a Finding."""

    owasp_category: str              # e.g. "A03:2021 - Injection"
    wstg_id: str                     # e.g. "WSTG-INPV-05"
    cwe_id: Optional[int]            # confirmed / corrected CWE
    risk: str                        # final risk after AI review
    confidence: str                  # final confidence after AI review
    false_positive_likelihood: str   # High/Medium/Low
    evidence_summary: str            # short plain-language explanation
    recommendation: str              # actionable remediation
    assessed_by: str                 # "ai:claude-..." or "static-mapping"
    black_box_note: str = ""         # coverage caveat, if relevant

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AssessedFinding:
    """A Finding paired with its Assessment — the unit the report renders."""

    finding: Finding
    assessment: Assessment

    def to_dict(self) -> dict[str, Any]:
        return {"finding": self.finding.to_dict(),
                "assessment": self.assessment.to_dict()}

    @property
    def sort_key(self) -> tuple:
        """Most severe, most confident first."""
        return (
            -RISK_ORDER.get(self.assessment.risk, 0),
            -RISK_ORDER.get(self.assessment.confidence + "", 0)
            if self.assessment.confidence in RISK_ORDER else 0,
        )
