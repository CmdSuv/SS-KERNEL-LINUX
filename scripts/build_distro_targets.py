#!/usr/bin/env python3
"""Multi-OS containerized build orchestrator for MC SS Sentinel (writes strictly to targets/<target_id>/)."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGETS_JSON = REPO_ROOT / "packaging" / "targets.json"


def load_targets() -> dict[str, dict[str, str]]:
    data = json.loads(TARGETS_JSON.read_text(encoding="utf-8"))
    return data["targets"]


def build_target(
    target_id: str,
    cfg: dict[str, str],
    dry_run: bool = False,
    no_cache: bool = False,
    cpus: str = "6",
    memory: str = "4g",
    cleanup_image: bool = False,
) -> int:
    dockerfile = REPO_ROOT / cfg["dockerfile"]
    image_tag = cfg["image_tag"]
    out_dir = REPO_ROOT / "targets" / target_id
    out_dir.mkdir(parents=True, exist_ok=True)

    # Guardrail: never allow output to target dev Bazzite dist/ or live user desktop binaries
    protected = {
        (REPO_ROOT / "dist").resolve(),
        (Path.home() / ".local" / "bin").resolve(),
    }
    if out_dir.resolve() in protected:
        print(f"[ERR] Refusing to write to protected path: {out_dir}", file=sys.stderr)
        return 2

    podman = shutil.which("podman")
    if not podman and not dry_run:
        print("[ERR] 'podman' not found in PATH.", file=sys.stderr)
        return 1
    podman_bin = podman or "podman"

    try:
        cpu_quota = max(100000, int(float(cpus) * 100000))
    except ValueError:
        cpu_quota = 600000

    build_cmd = [
        podman_bin,
        "build",
        "--cpu-period=100000",
        f"--cpu-quota={cpu_quota}",
        f"--memory={memory}",
        "-f",
        str(dockerfile),
        "-t",
        image_tag,
    ]
    if no_cache:
        build_cmd.append("--no-cache")
    build_cmd.append(str(REPO_ROOT / "packaging" / "dockerfiles"))

    run_cmd = [
        podman_bin,
        "run",
        "--rm",
        f"--cpus={cpus}",
        f"--memory={memory}",
        "-v",
        f"{REPO_ROOT}:/src:ro,Z",
        "-v",
        f"{out_dir}:/out/{target_id}:Z",
        image_tag,
        "/src/packaging/build_inside_container.sh",
        target_id,
    ]

    print(f"==> [{target_id}] {cfg['display_name']} -> {out_dir} (limit: {cpus} CPUs, {memory} RAM)")
    print("    BUILD:", " ".join(build_cmd))
    print("    RUN  :", " ".join(run_cmd))
    if dry_run:
        return 0

    cp_build = subprocess.run(build_cmd, check=False)
    if cp_build.returncode != 0:
        return cp_build.returncode
    cp_run = subprocess.run(run_cmd, check=False)
    if cp_run.returncode != 0:
        return cp_run.returncode
    if cleanup_image:
        print(f"    CLEAN: removing builder image {image_tag} & pruning intermediate layers...")
        subprocess.run([podman_bin, "rmi", "-f", image_tag], check=False)
        subprocess.run([podman_bin, "image", "prune", "-f"], check=False)
    return 0


def main(argv: list[str] | None = None) -> int:
    targets = load_targets()
    ap = argparse.ArgumentParser(description="Build per-OS MC SS Sentinel distributions cleanly in Podman.")
    ap.add_argument("--list", action="store_true", help="List available target IDs and exit.")
    ap.add_argument("--targets", type=str, default="", help="Comma-separated target IDs to build.")
    ap.add_argument("--all", action="store_true", help="Build all 7 distro targets.")
    ap.add_argument("--dry-run", action="store_true", help="Print container build/run commands without pulling or building.")
    ap.add_argument("--no-cache", action="store_true", help="Pass --no-cache to podman build.")
    ap.add_argument("--cpus", type=str, default="6", help="Max CPU cores per container (default: 6).")
    ap.add_argument("--memory", type=str, default="4g", help="Max RAM per container (default: 4g).")
    ap.add_argument("--cleanup-image", action="store_true", help="Permanently delete container builder image immediately after target succeeds.")
    args = ap.parse_args(argv)

    if args.list or (not args.all and not args.targets.strip()):
        print("Available MC SS Sentinel OS build targets:")
        for tid, cfg in targets.items():
            print(f"  - {tid:<14} | {cfg['display_name']} (glibc {cfg['glibc_floor']}, {cfg['base_image']})")
        return 0

    selected = list(targets.keys()) if args.all else [t.strip() for t in args.targets.split(",") if t.strip()]
    unknown = [t for t in selected if t not in targets]
    if unknown:
        print(f"[ERR] Unknown target IDs: {', '.join(unknown)}", file=sys.stderr)
        return 2

    for tid in selected:
        rc = build_target(
            tid,
            targets[tid],
            dry_run=args.dry_run,
            no_cache=args.no_cache,
            cpus=args.cpus,
            memory=args.memory,
            cleanup_image=args.cleanup_image,
        )
        if rc != 0:
            return rc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
