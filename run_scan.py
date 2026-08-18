#!/usr/bin/env python3
"""Orchestrator CLI — the full pipeline in one command.

    URL -> auth gate -> ZAP -> normalize -> AI assessment -> report

Example:
    export ANTHROPIC_API_KEY=sk-ant-...
    export SCAN_ALLOWLIST=localhost,juice-shop
    python run_scan.py --target http://localhost:3000 --out ./out

Use --no-ai to skip the Claude call (static mapping only) — handy for testing
the ZAP half without an API key.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from scanner import auth_gate, zap_runner, normalize, ai_assessor, report


def log(msg: str) -> None:
    print(msg, flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Black-box web vuln scanner (OWASP Top 10)")
    parser.add_argument("--target", required=True, help="target URL, e.g. http://localhost:3000")
    parser.add_argument("--out", default="./out", help="output directory (default ./out)")
    parser.add_argument("--allow", action="append", default=[],
                        help="add host to allowlist (repeatable); also reads SCAN_ALLOWLIST")
    parser.add_argument("--zap-proxy", default=os.environ.get("ZAP_PROXY", "http://127.0.0.1:8090"),
                        help="ZAP daemon proxy URL")
    parser.add_argument("--zap-api-key", default=os.environ.get("ZAP_API_KEY"),
                        help="ZAP API key (if the daemon requires one)")
    parser.add_argument("--timeout", type=int, default=1800, help="scan timeout seconds")
    parser.add_argument("--model", default=ai_assessor.DEFAULT_MODEL, help="Claude model id")
    parser.add_argument("--no-ai", action="store_true", help="skip AI, use static mapping only")
    parser.add_argument("--findings-json", help="skip ZAP; load raw ZAP alerts from this JSON file")
    args = parser.parse_args(argv)

    # 1) Authorization gate — fail closed before any traffic.
    allowlist = auth_gate.load_allowlist(args.allow)
    try:
        target = auth_gate.authorize(args.target, allowlist)
    except auth_gate.AuthorizationError as exc:
        log(f"[auth] DENIED: {exc}")
        return 2
    log(f"[auth] authorized: {target}")

    # 2) ZAP scan (or load pre-captured alerts for offline runs).
    if args.findings_json:
        log(f"[zap] loading alerts from {args.findings_json}")
        with open(args.findings_json, encoding="utf-8") as fh:
            raw_alerts = json.load(fh)
    else:
        try:
            runner = zap_runner.ZapRunner(
                proxy=args.zap_proxy, api_key=args.zap_api_key,
                timeout=args.timeout, on_progress=log,
            )
            raw_alerts = runner.scan(target)
        except zap_runner.ZapScanError as exc:
            log(f"[zap] ERROR: {exc}")
            return 3

    # 3) Normalize + dedupe -> JSON Findings.
    findings = normalize.normalize_zap(raw_alerts)
    log(f"[normalize] {len(findings)} unique findings")
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump([f.to_dict() for f in findings], fh, ensure_ascii=False, indent=2)

    # 4) AI assessment -> OWASP/WSTG/CWE + risk/confidence + remediation.
    assessed = ai_assessor.assess(
        findings, use_ai=not args.no_ai, model=args.model, on_progress=log,
    )
    with open(os.path.join(args.out, "assessment.json"), "w", encoding="utf-8") as fh:
        json.dump([af.to_dict() for af in assessed], fh, ensure_ascii=False, indent=2)

    # 5) Report.
    paths = report.write_reports(target, assessed, args.out)
    log(f"[report] {paths['html']}")
    log(f"[report] {paths['json']}")
    log("done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
