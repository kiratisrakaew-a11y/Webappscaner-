"""Drive an OWASP ZAP daemon through a black-box scan and return raw alerts.

This wraps the ZAP API (via the ``zapv2`` client) with the standard DAST
sequence: open the target, spider it to discover URLs, run the active scan
(the part that actually sends attack payloads), then pull the alerts.

The ZAP daemon itself is expected to already be running and reachable at
``proxy`` (docker-compose brings it up). We never launch ZAP in-process.

Scanning is long-running; every wait loop polls progress and honours an
overall ``timeout`` so a hung scan cannot block forever.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Optional

try:
    from zapv2 import ZAPv2  # type: ignore
except ImportError:  # pragma: no cover - import guard for a clearer error
    ZAPv2 = None  # resolved at call time with a helpful message


ProgressCb = Callable[[str], None]


class ZapScanError(RuntimeError):
    pass


class ZapRunner:
    def __init__(
        self,
        proxy: str = "http://127.0.0.1:8090",
        api_key: Optional[str] = None,
        timeout: int = 1800,
        poll_interval: int = 5,
        on_progress: Optional[ProgressCb] = None,
    ) -> None:
        if ZAPv2 is None:
            raise ZapScanError(
                "python-owasp-zap-v2.4 is not installed. "
                "Run: pip install -r requirements.txt"
            )
        self.timeout = timeout
        self.poll_interval = poll_interval
        self._log = on_progress or (lambda msg: None)
        # ZAP client talks to the daemon through its own proxy endpoint.
        self.zap = ZAPv2(
            apikey=api_key,
            proxies={"http": proxy, "https": proxy},
        )

    # -- public API ---------------------------------------------------------

    def scan(self, target: str) -> list[dict[str, Any]]:
        """Run spider + active scan against ``target`` and return raw alerts."""
        self._log(f"[zap] accessing target: {target}")
        self._access(target)
        self._spider(target)
        self._active_scan(target)
        alerts = self._alerts(target)
        self._log(f"[zap] collected {len(alerts)} raw alerts")
        return alerts

    # -- steps --------------------------------------------------------------

    def _access(self, target: str) -> None:
        # Prime ZAP's sites tree so spider/ascan have a starting node.
        self.zap.urlopen(target)
        time.sleep(2)

    def _spider(self, target: str) -> None:
        self._log("[zap] spidering...")
        scan_id = self.zap.spider.scan(target)
        self._wait(
            lambda: int(self.zap.spider.status(scan_id)),
            label="spider",
        )

    def _active_scan(self, target: str) -> None:
        self._log("[zap] active scanning (sending payloads)...")
        scan_id = self.zap.ascan.scan(target)
        # ascan.scan returns an error string instead of an id if it can't start.
        if not str(scan_id).isdigit():
            raise ZapScanError(f"ZAP active scan failed to start: {scan_id!r}")
        self._wait(
            lambda: int(self.zap.ascan.status(scan_id)),
            label="active-scan",
        )

    def _alerts(self, target: str) -> list[dict[str, Any]]:
        return self.zap.core.alerts(baseurl=target)

    # -- helpers ------------------------------------------------------------

    def _wait(self, progress_fn: Callable[[], int], label: str) -> None:
        """Poll ``progress_fn`` (0-100) until 100 or timeout."""
        deadline = time.time() + self.timeout
        last = -1
        while True:
            pct = progress_fn()
            if pct != last:
                self._log(f"[zap] {label}: {pct}%")
                last = pct
            if pct >= 100:
                return
            if time.time() > deadline:
                raise ZapScanError(
                    f"ZAP {label} timed out after {self.timeout}s at {pct}%"
                )
            time.sleep(self.poll_interval)
