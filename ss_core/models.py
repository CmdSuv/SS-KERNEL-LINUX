"""Core data models, severity scoring, and ScanContext abstraction."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


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

    @property
    def effective_score(self) -> float:
        return round(self.severity.base_weight * self.confidence.multiplier, 2)

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

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_error(self, engine: str, msg: str) -> None:
        self.errors.append(f"[{engine}] {msg}")
