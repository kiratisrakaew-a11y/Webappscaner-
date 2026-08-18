"""Render the Web Security Assessment Report (HTML) and machine JSON.

The HTML is a single self-contained file (inline CSS, no external assets) so it
can be opened directly or later served from Cloud Storage. It leads with a
summary + the black-box coverage caveat, then one card per finding ordered
most-severe first.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from .models import AssessedFinding, RISK_ORDER
from . import mappings


RISK_COLORS = {
    "Critical": "#7c1d1d", "High": "#b91c1c", "Medium": "#c2660c",
    "Low": "#2563eb", "Informational": "#4b5563", "Unknown": "#4b5563",
}


def build_json(target: str, assessed: list[AssessedFinding]) -> dict[str, Any]:
    """Machine-readable report payload."""
    return {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": _summary(assessed),
        "findings": [af.to_dict() for af in assessed],
    }


def _summary(assessed: list[AssessedFinding]) -> dict[str, Any]:
    risks = Counter(af.assessment.risk for af in assessed)
    cats = Counter(af.assessment.owasp_category for af in assessed)
    return {
        "total": len(assessed),
        "by_risk": dict(risks),
        "by_owasp_category": dict(cats),
    }


def _e(s: Any) -> str:
    return html.escape(str(s if s is not None else ""))


def _risk_badge(risk: str) -> str:
    color = RISK_COLORS.get(risk, "#4b5563")
    return (f'<span class="badge" style="background:{color}">{_e(risk)}</span>')


def _finding_card(idx: int, af: AssessedFinding) -> str:
    f, a = af.finding, af.assessment
    cwe = f"CWE-{a.cwe_id}" if a.cwe_id else "CWE-?"
    fp = a.false_positive_likelihood
    note = a.black_box_note
    note_html = (f'<p class="note">🔎 <strong>Black-box coverage:</strong> '
                 f'{_e(note)}</p>') if note else ""
    return f"""
    <section class="card">
      <div class="card-head">
        <h3>{idx}. {_e(f.name)}</h3>
        <div>{_risk_badge(a.risk)}
             <span class="badge conf">Confidence: {_e(a.confidence)}</span>
             <span class="badge fp">FP likelihood: {_e(fp)}</span></div>
      </div>
      <table class="meta">
        <tr><th>OWASP Top 10</th><td>{_e(a.owasp_category)}</td></tr>
        <tr><th>WSTG</th><td>{_e(a.wstg_id)}</td></tr>
        <tr><th>CWE</th><td>{_e(cwe)}</td></tr>
        <tr><th>URL</th><td class="mono">{_e(f.url)}</td></tr>
        {f'<tr><th>Parameter</th><td class="mono">{_e(f.param)}</td></tr>' if f.param else ''}
        {f'<tr><th>Attack</th><td class="mono">{_e(f.attack)}</td></tr>' if f.attack else ''}
        <tr><th>Assessed by</th><td>{_e(a.assessed_by)}</td></tr>
      </table>
      <h4>ผลการประเมิน (Evidence)</h4>
      <p>{_e(a.evidence_summary)}</p>
      {f'<pre class="evidence">{_e(f.evidence)}</pre>' if f.evidence else ''}
      <h4>คำแนะนำในการแก้ไข (Recommendation)</h4>
      <p>{_e(a.recommendation)}</p>
      {note_html}
    </section>"""


def _summary_rows(summary: dict[str, Any]) -> str:
    rows = []
    for risk in sorted(summary["by_risk"], key=lambda r: -RISK_ORDER.get(r, 0)):
        count = summary["by_risk"][risk]
        rows.append(f"<tr><td>{_risk_badge(risk)}</td><td>{count}</td></tr>")
    return "\n".join(rows)


def _category_rows(summary: dict[str, Any]) -> str:
    rows = []
    for cat, count in sorted(summary["by_owasp_category"].items()):
        cov = mappings.coverage_note(cat)
        rows.append(
            f"<tr><td>{_e(cat)}</td><td>{count}</td><td>{_e(cov)}</td></tr>"
        )
    return "\n".join(rows)


def build_html(target: str, assessed: list[AssessedFinding]) -> str:
    summary = _summary(assessed)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cards = "\n".join(_finding_card(i + 1, af) for i, af in enumerate(assessed))
    if not assessed:
        cards = '<p class="empty">ไม่พบ finding — แต่ black-box scan ไม่ครอบคลุมทุกหมวด (ดูตารางด้านบน)</p>'

    return f"""<!doctype html>
<html lang="th"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Web Security Assessment Report — {_e(target)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, "Segoe UI", Roboto, "Noto Sans Thai", sans-serif;
         margin: 0; background: #f5f6f8; color: #1a1a1a; line-height: 1.6; }}
  header {{ background: #0f172a; color: #fff; padding: 28px 24px; }}
  header h1 {{ margin: 0 0 6px; font-size: 22px; }}
  header .sub {{ opacity: .8; font-size: 14px; }}
  main {{ max-width: 960px; margin: 0 auto; padding: 24px 16px 64px; }}
  .panel {{ background: #fff; border: 1px solid #e2e5ea; border-radius: 10px;
            padding: 18px 20px; margin-bottom: 20px; }}
  h2 {{ font-size: 17px; border-bottom: 2px solid #0f172a; padding-bottom: 6px; }}
  table {{ width: 100%; border-collapse: collapse; }}
  .panel table td, .panel table th {{ padding: 6px 8px; border-bottom: 1px solid #eef0f3;
                                       text-align: left; vertical-align: top; }}
  .meta th {{ width: 130px; color: #555; font-weight: 600; }}
  .badge {{ display: inline-block; color: #fff; padding: 2px 9px; border-radius: 20px;
            font-size: 12px; font-weight: 600; margin-right: 4px; }}
  .badge.conf, .badge.fp {{ background: #475569; }}
  .card {{ background: #fff; border: 1px solid #e2e5ea; border-left: 5px solid #94a3b8;
           border-radius: 10px; padding: 16px 20px; margin-bottom: 16px; }}
  .card-head {{ display: flex; justify-content: space-between; align-items: flex-start;
                flex-wrap: wrap; gap: 8px; }}
  .card h3 {{ margin: 0; font-size: 16px; }}
  .card h4 {{ margin: 14px 0 4px; font-size: 13px; text-transform: uppercase;
              letter-spacing: .04em; color: #64748b; }}
  .mono {{ font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 13px;
           word-break: break-all; }}
  pre.evidence {{ background: #0f172a; color: #e2e8f0; padding: 10px 12px;
                  border-radius: 6px; overflow-x: auto; font-size: 12px; }}
  .note {{ background: #fef9c3; border-radius: 6px; padding: 8px 12px; font-size: 13px; }}
  .empty {{ color: #64748b; }}
  .disclaimer {{ font-size: 13px; color: #92400e; background: #fffbeb;
                 border: 1px solid #fde68a; border-radius: 8px; padding: 12px 16px; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #0b1220; color: #e5e7eb; }}
    .panel, .card {{ background: #111a2e; border-color: #1f2b45; }}
    .meta th {{ color: #9aa7bd; }}
    .panel table td, .panel table th {{ border-color: #1f2b45; }}
    .note {{ background: #3b3413; color: #fde68a; }}
    .disclaimer {{ background: #2a1e08; color: #fcd34d; border-color: #4a3a12; }}
  }}
</style></head>
<body>
<header>
  <h1>🛡️ Web Security Assessment Report</h1>
  <div class="sub">Target: {_e(target)} &nbsp;·&nbsp; Generated: {generated}
     &nbsp;·&nbsp; Method: Black-box DAST (OWASP ZAP + AI assessment)</div>
</header>
<main>
  <div class="panel">
    <h2>สรุปผล (Summary)</h2>
    <p>พบทั้งหมด <strong>{summary['total']}</strong> รายการ</p>
    <table>{_summary_rows(summary)}</table>
  </div>

  <div class="panel">
    <h2>การจัดหมวดตาม OWASP Top 10 (2021) + ขอบเขต black-box</h2>
    <table>
      <tr><th>หมวด</th><th>จำนวน</th><th>ความครอบคลุมของ black-box</th></tr>
      {_category_rows(summary)}
    </table>
  </div>

  <div class="panel">
    <h2>รายละเอียดช่องโหว่ (Findings)</h2>
    {cards}
  </div>

  <div class="disclaimer">
    ⚠️ รายงานนี้มาจากการทดสอบแบบ black-box (DAST) จึงตรวจไม่ครบทุกหมวดของ OWASP Top 10 —
    หมวด A04 (Insecure Design), A09 (Logging/Monitoring) และบางส่วนของ A01/A06/A07/A08
    ต้องอาศัยการตรวจสอบเพิ่มเติม (source code review / threat modeling) การไม่พบช่องโหว่ในหมวดใด
    ไม่ได้แปลว่าปลอดภัยในหมวดนั้น การประเมินด้วย AI ควรผ่านการตรวจทานโดยผู้เชี่ยวชาญก่อนตัดสินใจ
  </div>
</main>
</body></html>"""


def write_reports(target: str, assessed: list[AssessedFinding], out_dir: str) -> dict[str, str]:
    """Write report.html + report.json into out_dir, return their paths."""
    import os
    os.makedirs(out_dir, exist_ok=True)
    html_path = os.path.join(out_dir, "report.html")
    json_path = os.path.join(out_dir, "report.json")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(build_html(target, assessed))
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(build_json(target, assessed), fh, ensure_ascii=False, indent=2)
    return {"html": html_path, "json": json_path}
