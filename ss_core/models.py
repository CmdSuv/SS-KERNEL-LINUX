"""Core data models, severity scoring, and ScanContext abstraction."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
import threading
from typing import Any, Callable


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def base_weight(self) -> int:
        return {
            Severity.CRITICAL: 42,
            Severity.HIGH: 24,
            Severity.MEDIUM: 12,
            Severity.LOW: 5,
            Severity.INFO: 0,
        }[self]

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def multiplier(self) -> float:
        return {
            Confidence.CONFIRMED: 1.0,
            Confidence.HIGH: 0.85,
            Confidence.MEDIUM: 0.60,
            Confidence.LOW: 0.35,
        }[self]


class ScanStatus(str, Enum):
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    UNSUPPORTED = "UNSUPPORTED"
    TIMED_OUT = "TIMED_OUT"
    ERROR = "ERROR"
    CANCELLED = "CANCELLED"
    SKIPPED = "SKIPPED"


@dataclass
class Finding:
    rule_id: str
    engine: str
    severity: Severity
    confidence: Confidence
    category: str
    title: str
    description: str
    evidence: list[str] = field(default_factory=list)
    path: str | None = None
    pid: int | None = None
    recommendation: str = ""
    timestamp_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.severity, Severity):
            self.severity = Severity(str(self.severity).upper())
        if not isinstance(self.confidence, Confidence):
            self.confidence = Confidence(str(self.confidence).upper())
        if self.evidence is None:
            self.evidence = []
        if self.metadata is None:
            self.metadata = {}

    @property
    def effective_score(self) -> float:
        return round(self.severity.base_weight * self.confidence.multiplier, 2)

    @property
    def dedup_key(self) -> tuple[str, str, int | None, str]:
        return (self.rule_id, self.path or "", self.pid, self.title)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "engine": self.engine,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "path": self.path,
            "pid": self.pid,
            "recommendation": self.recommendation,
            "timestamp_utc": self.timestamp_utc,
            "effective_score": self.effective_score,
            "metadata": self.metadata,
        }


@dataclass
class ScanContext:
    """Target environment & runtime configuration for all forensic engines.

    Abstracting `home_dir`, `root_prefix`, and `proc_root` allows both full live
    system audits and deterministic isolated adversarial simulations.
    """

    home_dir: Path = field(default_factory=Path.home)
    root_prefix: Path = field(default_factory=lambda: Path("/"))
    proc_root: Path = field(default_factory=lambda: Path("/proc"))
    live_mode: bool = True
    enable_memory_scan: bool = True
    enable_kernel_lkm: bool = False
    kernel_trace_ms: int = 1500
    kernel_snapshot_data: dict[str, Any] | None = None
    target_os: str = "auto"
    time_window_hours: float = 2.0
    max_file_scan_bytes: int = 32 * 1024 * 1024
    max_mem_scan_bytes_per_proc: int = 256 * 1024 * 1024
    deep_home_scan: bool = True
    scan_started_utc: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    now_epoch: float | None = None  # Overrideable in simulation for deterministic clocks
    findings: list[Finding] = field(default_factory=list)
    telemetry: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    cancel_event: threading.Event | None = field(default=None, repr=False, compare=False)
    _engine_progress_cb: Callable[[float, str], None] | None = field(
        default=None, init=False, repr=False, compare=False
    )
    _finding_index: dict[tuple[str, str, int | None, str], int] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )

    def current_epoch(self) -> float:
        if self.now_epoch is not None:
            return self.now_epoch
        return self.scan_started_utc.timestamp()

    def sys_path(self, absolute_unix_path: str) -> Path:
        """Map an OS absolute path (e.g. '/etc/hosts') onto `root_prefix`."""
        stripped = absolute_unix_path.lstrip("/")
        if str(self.root_prefix) == "/":
            return Path("/") / stripped
        return self.root_prefix / stripped

    def request_cancel(self) -> None:
        if self.cancel_event is None:
            self.cancel_event = threading.Event()
        self.cancel_event.set()

    def is_cancelled(self) -> bool:
        return bool(self.cancel_event is not None and self.cancel_event.is_set())

    def set_engine_status(
        self,
        engine_code: str,
        status: ScanStatus | str,
        detail: str = "",
    ) -> None:
        st_val = status.value if isinstance(status, ScanStatus) else str(status)
        statuses: dict[str, dict[str, str]] = self.telemetry.setdefault("engine_status", {})
        statuses[engine_code] = {"status": st_val, "detail": detail}

    def set_coverage(
        self,
        component: str,
        status: ScanStatus | str,
        detail: str = "",
        counts: dict[str, Any] | None = None,
    ) -> None:
        st_val = status.value if isinstance(status, ScanStatus) else str(status)
        cov: dict[str, dict[str, Any]] = self.telemetry.setdefault("scan_coverage", {})
        entry: dict[str, Any] = {"status": st_val, "detail": detail}
        if counts:
            entry["counts"] = dict(counts)
        cov[component] = entry

    @property
    def engine_status(self) -> dict[str, dict[str, str]]:
        raw = self.telemetry.get("engine_status")
        return dict(raw) if isinstance(raw, dict) else {}

    @property
    def coverage(self) -> dict[str, dict[str, Any]]:
        raw = self.telemetry.get("scan_coverage")
        return dict(raw) if isinstance(raw, dict) else {}

    def add_finding(self, finding: Finding) -> None:
        key = finding.dedup_key
        existing_idx = self._finding_index.get(key)
        if existing_idx is not None and 0 <= existing_idx < len(self.findings):
            existing = self.findings[existing_idx]
            if finding.severity.rank > existing.severity.rank:
                existing.severity = finding.severity
            if finding.confidence.multiplier > existing.confidence.multiplier:
                existing.confidence = finding.confidence
            existing_ev = set(existing.evidence)
            for item in finding.evidence:
                if item not in existing_ev and len(existing.evidence) < 30:
                    existing.evidence.append(item)
                    existing_ev.add(item)
            if finding.metadata:
                for mk, mv in finding.metadata.items():
                    existing.metadata.setdefault(mk, mv)
            return
        self._finding_index[key] = len(self.findings)
        self.findings.append(finding)

    def add_error(self, engine: str, msg: str) -> None:
        self.errors.append(f"[{engine}] {msg}")
