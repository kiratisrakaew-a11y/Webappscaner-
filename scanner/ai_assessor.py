"""AI assessment layer — turn raw findings into risk-rated, remediated results.

Design principle (see mappings.py): the OWASP category / WSTG id / CWE are
resolved by the static ground-truth tables FIRST, then handed to Claude as
context. Claude's job is to:
    * read the evidence and judge false-positive likelihood,
    * settle a final risk + confidence,
    * write a plain-language explanation and actionable remediation,
    * confirm (or, with justification, correct) the resolved CWE/category.

It must not invent evidence the scanner didn't produce — the prompt says so
explicitly, and everything it returns is anchored to a real Finding.

If no API key is available (or ``use_ai=False``), ``assess`` falls back to a
purely static assessment so the pipeline still produces a full report.
"""

from __future__ import annotations

import json
import os
from typing import Optional

from .models import Finding, Assessment, AssessedFinding
from . import mappings

try:
    import anthropic  # type: ignore
except ImportError:  # pragma: no cover
    anthropic = None


DEFAULT_MODEL = os.environ.get("ASSESS_MODEL", "claude-sonnet-5")

SYSTEM_PROMPT = """\
You are a senior application security analyst reviewing the output of a
black-box DAST scan (OWASP ZAP). You will receive a batch of findings. For
each finding you are given the scanner's data AND a pre-resolved OWASP Top 10
2021 category, WSTG id, and CWE from an authoritative lookup table.

Your job for each finding:
1. Judge false_positive_likelihood (High/Medium/Low) from the evidence. DAST
   tools over-report; be honest.
2. Decide a final risk (Critical/High/Medium/Low/Informational) and confidence
   (High/Medium/Low), starting from the scanner's values and adjusting only
   with justification from the evidence.
3. Keep the provided owasp_category / wstg_id / cwe_id UNLESS they are clearly
   wrong for the finding — if you change one, it must be defensible.
4. Write evidence_summary: 1-2 sentences, plain language, describing what was
   actually observed. Do NOT fabricate evidence beyond what is given.
5. Write recommendation: concrete, actionable remediation for developers.

Return ONLY a JSON array, one object per finding in the same order, each:
{"index": int, "owasp_category": str, "wstg_id": str, "cwe_id": int|null,
 "risk": str, "confidence": str, "false_positive_likelihood": str,
 "evidence_summary": str, "recommendation": str}
No prose outside the JSON array.
"""


def _static_assessment(finding: Finding) -> Assessment:
    """Assessment without AI — pure static mapping, scanner values passed through."""
    category, wstg, cwe = mappings.resolve_owasp(finding)
    return Assessment(
        owasp_category=category,
        wstg_id=wstg,
        cwe_id=cwe,
        risk=finding.risk,
        confidence=finding.confidence,
        false_positive_likelihood="Unknown",
        evidence_summary=(finding.evidence or finding.description or "")[:400],
        recommendation=finding.solution or "ดูคำแนะนำจาก reference ของ scanner",
        assessed_by="static-mapping",
        black_box_note=mappings.coverage_note(category),
    )


def _finding_payload(index: int, finding: Finding) -> dict:
    """Compact record sent to the model, with resolved ground truth attached."""
    category, wstg, cwe = mappings.resolve_owasp(finding)
    return {
        "index": index,
        "resolved_owasp_category": category,
        "resolved_wstg_id": wstg,
        "resolved_cwe_id": cwe,
        "scanner": {
            "name": finding.name,
            "risk": finding.risk,
            "confidence": finding.confidence,
            "url": finding.url,
            "param": finding.param,
            "attack": finding.attack,
            "evidence": finding.evidence[:800],
            "description": finding.description[:800],
        },
    }


def _parse_response(text: str) -> list[dict]:
    """Extract the JSON array from the model response, tolerant of stray text."""
    text = text.strip()
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end == -1:
        raise ValueError("no JSON array in model response")
    return json.loads(text[start : end + 1])


def _ai_batch(findings: list[Finding], client, model: str) -> list[Assessment]:
    payload = [_finding_payload(i, f) for i, f in enumerate(findings)]
    message = client.messages.create(
        model=model,
        max_tokens=8000,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": "Findings to assess:\n" + json.dumps(payload, ensure_ascii=False),
        }],
    )
    text = "".join(block.text for block in message.content if block.type == "text")
    parsed = _parse_response(text)

    by_index = {int(item.get("index", i)): item for i, item in enumerate(parsed)}
    results: list[Assessment] = []
    for i, finding in enumerate(findings):
        item = by_index.get(i)
        if item is None:
            results.append(_static_assessment(finding))  # model dropped one
            continue
        category = item.get("owasp_category") or _static_assessment(finding).owasp_category
        results.append(Assessment(
            owasp_category=category,
            wstg_id=item.get("wstg_id", ""),
            cwe_id=item.get("cwe_id"),
            risk=item.get("risk", finding.risk),
            confidence=item.get("confidence", finding.confidence),
            false_positive_likelihood=item.get("false_positive_likelihood", "Unknown"),
            evidence_summary=item.get("evidence_summary", ""),
            recommendation=item.get("recommendation", ""),
            assessed_by=f"ai:{model}",
            black_box_note=mappings.coverage_note(category),
        ))
    return results


def assess(
    findings: list[Finding],
    use_ai: bool = True,
    api_key: Optional[str] = None,
    model: str = DEFAULT_MODEL,
    batch_size: int = 15,
    on_progress=None,
) -> list[AssessedFinding]:
    """Assess all findings, returning AssessedFinding sorted most-severe first."""
    log = on_progress or (lambda m: None)
    key = api_key or os.environ.get("ANTHROPIC_API_KEY")

    if not findings:
        return []

    if not use_ai or anthropic is None or not key:
        if use_ai and not key:
            log("[ai] no ANTHROPIC_API_KEY — falling back to static mapping")
        elif use_ai and anthropic is None:
            log("[ai] anthropic SDK not installed — falling back to static mapping")
        assessments = [_static_assessment(f) for f in findings]
    else:
        client = anthropic.Anthropic(api_key=key)
        assessments = []
        for start in range(0, len(findings), batch_size):
            batch = findings[start : start + batch_size]
            log(f"[ai] assessing findings {start + 1}-{start + len(batch)} of {len(findings)}")
            try:
                assessments.extend(_ai_batch(batch, client, model))
            except Exception as exc:  # never let one bad batch sink the run
                log(f"[ai] batch failed ({exc}); using static mapping for it")
                assessments.extend(_static_assessment(f) for f in batch)

    assessed = [AssessedFinding(f, a) for f, a in zip(findings, assessments)]
    assessed.sort(key=lambda af: af.sort_key)
    return assessed
