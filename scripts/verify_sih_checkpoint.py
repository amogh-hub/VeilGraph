#!/usr/bin/env python3
"""Single-command verification harness for VeilGraph SIH26171.

Runs the browser, privacy, backend, frontend, contract-determinism and repository
integrity gates and writes compact human-readable + JSON evidence.

The harness intentionally keeps detailed command output in per-gate log files so
local verification does not require copy-pasting hundreds of terminal lines.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
REPORT_ROOT = ROOT / "artifacts" / "verification"
LOG_ROOT = REPORT_ROOT / "logs"

FOCUSED_BROWSER_TESTS = [
    "tests/test_browser_capture_api.py",
    "tests/test_browser_local_analysis.py",
    "tests/test_browser_pairing.py",
    "tests/test_browser_privacy_pipeline.py",
    "tests/test_browser_release_gate.py",
    "tests/test_browser_reasoning.py",
]


@dataclass
class GateResult:
    name: str
    status: str
    duration_seconds: float
    command: str
    log: str
    summary: str = ""
    return_code: int | None = None


class Harness:
    def __init__(self, *, quick: bool, ci: bool) -> None:
        self.quick = quick
        self.ci = ci
        self.results: list[GateResult] = []
        self.started = time.monotonic()
        self.timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        self.backend_python = self._resolve_backend_python()
        REPORT_ROOT.mkdir(parents=True, exist_ok=True)
        LOG_ROOT.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _resolve_backend_python() -> str:
        override = os.environ.get("VEILGRAPH_BACKEND_PYTHON")
        if override:
            return override
        candidate = ROOT / "backend" / ".venv" / "bin" / "python"
        if candidate.exists():
            return str(candidate)
        return sys.executable

    @staticmethod
    def _command_text(command: Iterable[str]) -> str:
        return " ".join(subprocess.list2cmdline([part]) for part in command)

    @staticmethod
    def _safe_name(name: str) -> str:
        return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")

    def _print_result(self, result: GateResult) -> None:
        icon = "PASS" if result.status == "PASS" else ("SKIP" if result.status == "SKIP" else "FAIL")
        suffix = f" — {result.summary}" if result.summary else ""
        print(f"[{icon:4}] {result.name:<38} {result.duration_seconds:7.2f}s{suffix}")

    def run_command(
        self,
        name: str,
        command: list[str],
        *,
        cwd: Path | None = None,
        summary_parser=None,
        env: dict[str, str] | None = None,
    ) -> GateResult:
        started = time.monotonic()
        log_path = LOG_ROOT / f"{len(self.results)+1:02d}-{self._safe_name(name)}.log"
        command_text = self._command_text(command)
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        try:
            completed = subprocess.run(
                command,
                cwd=str(cwd or ROOT),
                env=merged_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                check=False,
            )
            output = completed.stdout or ""
            return_code = completed.returncode
        except FileNotFoundError as exc:
            output = f"Executable not found: {exc}\n"
            return_code = 127
        except Exception as exc:  # defensive evidence capture
            output = f"Harness exception: {type(exc).__name__}: {exc}\n"
            return_code = 126
        log_path.write_text(
            f"COMMAND: {command_text}\nCWD: {cwd or ROOT}\n\n{output}",
            encoding="utf-8",
        )
        summary = ""
        if summary_parser:
            try:
                summary = summary_parser(output)
            except Exception:
                summary = ""
        result = GateResult(
            name=name,
            status="PASS" if return_code == 0 else "FAIL",
            duration_seconds=round(time.monotonic() - started, 3),
            command=command_text,
            log=str(log_path.relative_to(ROOT)),
            summary=summary,
            return_code=return_code,
        )
        self.results.append(result)
        self._print_result(result)
        return result

    def run_python_gate(self, name: str, fn, *, command: str) -> GateResult:
        started = time.monotonic()
        log_path = LOG_ROOT / f"{len(self.results)+1:02d}-{self._safe_name(name)}.log"
        try:
            ok, summary, details = fn()
            code = 0 if ok else 1
        except Exception as exc:
            ok, summary, details, code = False, f"{type(exc).__name__}: {exc}", "", 1
        log_path.write_text(f"COMMAND: {command}\n\n{details}\n", encoding="utf-8")
        result = GateResult(
            name=name,
            status="PASS" if ok else "FAIL",
            duration_seconds=round(time.monotonic() - started, 3),
            command=command,
            log=str(log_path.relative_to(ROOT)),
            summary=summary,
            return_code=code,
        )
        self.results.append(result)
        self._print_result(result)
        return result

    def skip(self, name: str, summary: str) -> None:
        result = GateResult(name, "SKIP", 0.0, "", "", summary, None)
        self.results.append(result)
        self._print_result(result)

    @staticmethod
    def _pytest_summary(output: str) -> str:
        matches = re.findall(r"(\d+) passed(?:,\s*(\d+) warnings?)?", output)
        if not matches:
            return ""
        passed, warnings = matches[-1]
        return f"{passed} passed" + (f", {warnings} warnings" if warnings else "")

    @staticmethod
    def _audit_summary(output: str) -> str:
        match = re.search(r"found\s+(\d+)\s+vulnerabilit", output, re.I)
        if match:
            return f"{match.group(1)} vulnerabilities"
        if "0 vulnerabilities" in output:
            return "0 vulnerabilities"
        return ""

    def contract_determinism(self) -> tuple[bool, str, str]:
        log_chunks: list[str] = []

        def execute(label: str, command: list[str], cwd: Path) -> tuple[int, str]:
            completed = subprocess.run(
                command,
                cwd=str(cwd),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                check=False,
                env={**os.environ, **({"PYTHONPATH": "."} if cwd == backend else {})},
            )
            text = completed.stdout or ""
            log_chunks.append(f"## {label}\n$ {self._command_text(command)}\n{text}\n")
            return completed.returncode, text

        backend = ROOT / "backend"
        frontend = ROOT / "frontend"
        openapi = backend / "openapi.json"
        schema = frontend / "src" / "api" / "schema.d.ts"

        first = execute("OpenAPI generation #1", [self.backend_python, "export_openapi.py"], backend)
        if first[0] != 0:
            return False, "OpenAPI generation failed", "\n".join(log_chunks)
        first_types = execute("TS schema generation #1", ["npm", "run", "generate:api"], frontend)
        if first_types[0] != 0:
            return False, "Type-schema generation failed", "\n".join(log_chunks)
        if not openapi.exists() or not schema.exists():
            return False, "Generated contract file missing", "\n".join(log_chunks)

        openapi_snapshot = openapi.read_bytes()
        schema_snapshot = schema.read_bytes()

        second = execute("OpenAPI generation #2", [self.backend_python, "export_openapi.py"], backend)
        second_types = execute("TS schema generation #2", ["npm", "run", "generate:api"], frontend)
        if second[0] != 0 or second_types[0] != 0:
            return False, "Second generation failed", "\n".join(log_chunks)

        openapi_same = openapi.read_bytes() == openapi_snapshot
        schema_same = schema.read_bytes() == schema_snapshot
        details = "\n".join(log_chunks)
        details += f"\nOpenAPI deterministic: {openapi_same}\nType schema deterministic: {schema_same}\n"
        return openapi_same and schema_same, "OpenAPI + TS schema stable" if openapi_same and schema_same else "Generated contracts drifted", details

    def environment_snapshot(self) -> dict[str, str]:
        def version(command: list[str]) -> str:
            try:
                out = subprocess.check_output(command, cwd=str(ROOT), stderr=subprocess.STDOUT, text=True, timeout=15)
                return out.strip().splitlines()[0]
            except Exception as exc:
                return f"unavailable ({type(exc).__name__})"

        return {
            "platform": platform.platform(),
            "python_runner": sys.version.split()[0],
            "backend_python": version([self.backend_python, "--version"]),
            "git": version(["git", "--version"]),
            "node": version(["node", "--version"]),
            "npm": version(["npm", "--version"]),
            "tesseract": version(["tesseract", "--version"]),
            "pdftotext": version(["pdftotext", "-v"]),
        }

    def git_snapshot(self) -> dict[str, object]:
        def capture(command: list[str]) -> str:
            try:
                return subprocess.check_output(command, cwd=str(ROOT), text=True, stderr=subprocess.STDOUT).strip()
            except Exception:
                return ""

        return {
            "branch": capture(["git", "branch", "--show-current"]),
            "commit": capture(["git", "rev-parse", "HEAD"]),
            "describe": capture(["git", "describe", "--always", "--dirty", "--tags"]),
            "status_porcelain": capture(["git", "status", "--porcelain=v1"]).splitlines(),
        }

    def run(self) -> int:
        print("VeilGraph SIH26171 Verification Harness")
        print("=" * 72)
        print(f"Mode: {'CI' if self.ci else ('QUICK' if self.quick else 'FULL')}\n")

        self.run_command("Git diff integrity (pre)", ["git", "diff", "--check", "HEAD"])

        ext = ROOT / "browser-extension"
        frontend = ROOT / "frontend"
        backend = ROOT / "backend"

        self.run_command("Extension dependency audit", ["npm", "audit", "--audit-level=moderate"], cwd=ext, summary_parser=self._audit_summary)
        self.run_command("Extension TypeScript", ["npm", "run", "typecheck"], cwd=ext)
        self.run_command("Extension production build", ["npm", "run", "build"], cwd=ext)
        self.run_command("Learned local model contract", ["node", "scripts/verify_learned_model_contract.mjs"], cwd=ext)
        self.run_command("Perception + visual contract", ["npm", "run", "verify:perception"], cwd=ext)

        self.run_command("Python↔browser interoperability", [self.backend_python, "scripts/verify_browser_protocol_interop.py"], cwd=ROOT)
        self.run_command("Typed action-plan contract", ["npm", "run", "verify:action-plan"], cwd=ext)

        focused = [self.backend_python, "-m", "pytest", *FOCUSED_BROWSER_TESTS, "-q"]
        self.run_command("Browser/privacy regression", focused, cwd=backend, summary_parser=self._pytest_summary, env={"PYTHONPATH": "."})

        if self.quick:
            self.skip("Full backend regression", "skipped by --quick")
        else:
            self.run_command(
                "Full backend regression",
                [self.backend_python, "-m", "pytest", "tests", "-q"],
                cwd=backend,
                summary_parser=self._pytest_summary,
                env={"PYTHONPATH": "."},
            )

        self.run_command("Frontend dependency audit", ["npm", "audit", "--audit-level=moderate"], cwd=frontend, summary_parser=self._audit_summary)
        self.run_command("Frontend TypeScript", ["npm", "run", "typecheck"], cwd=frontend)
        self.run_command("Frontend production build", ["npm", "run", "build"], cwd=frontend)

        self.run_python_gate("Generated contract determinism", self.contract_determinism, command="generate OpenAPI + TS schema twice and byte-compare")
        self.run_command("Git diff integrity (final)", ["git", "diff", "--check", "HEAD"])

        if self.ci:
            def clean_checkout() -> tuple[bool, str, str]:
                completed = subprocess.run(
                    ["git", "status", "--porcelain=v1"], cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False
                )
                output = completed.stdout or ""
                ok = completed.returncode == 0 and not output.strip()
                return ok, "generated/build outputs committed" if ok else "verification changed tracked/untracked files", output
            self.run_python_gate("CI checkout drift", clean_checkout, command="git status --porcelain=v1 must be empty")

        elapsed = round(time.monotonic() - self.started, 3)
        failed = [r for r in self.results if r.status == "FAIL"]
        passed = [r for r in self.results if r.status == "PASS"]
        skipped = [r for r in self.results if r.status == "SKIP"]
        overall = ("QUICK_PASS" if self.quick else "VALIDATED") if not failed else "FAILED"

        report = {
            "schema_version": 1,
            "project": "VeilGraph",
            "problem_statement": "SIH26171",
            "verification_mode": "ci" if self.ci else ("quick" if self.quick else "full"),
            "started_at_utc": self.timestamp,
            "duration_seconds": elapsed,
            "overall_status": overall,
            "summary": {"passed": len(passed), "failed": len(failed), "skipped": len(skipped)},
            "environment": self.environment_snapshot(),
            "git": self.git_snapshot(),
            "gates": [asdict(r) for r in self.results],
        }
        latest_json = REPORT_ROOT / "latest.json"
        latest_txt = REPORT_ROOT / "latest.txt"
        latest_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        lines = [
            "VEILGRAPH SIH26171 CHECKPOINT",
            "=" * 72,
            *[
                f"{r.status:<4}  {r.name:<38} {r.duration_seconds:7.2f}s" + (f"  {r.summary}" if r.summary else "")
                for r in self.results
            ],
            "=" * 72,
            f"RESULT: {overall}",
            f"GATES: {len(passed)} passed / {len(failed)} failed / {len(skipped)} skipped",
            f"RUNTIME: {elapsed:.2f}s",
            f"REPORT: {latest_json.relative_to(ROOT)}",
        ]
        latest_txt.write_text("\n".join(lines) + "\n", encoding="utf-8")

        print("\n" + "=" * 72)
        print(f"RESULT: {overall}")
        print(f"GATES: {len(passed)} passed / {len(failed)} failed / {len(skipped)} skipped")
        print(f"RUNTIME: {elapsed:.2f}s")
        print(f"REPORT: {latest_json.relative_to(ROOT)}")
        if failed:
            print("\nFailed gates:")
            for result in failed:
                print(f"  - {result.name}: {result.log}")
            print("\nShare artifacts/verification/latest.json; detailed logs stay local unless needed.")
        return 0 if not failed else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify the VeilGraph SIH26171 engineering checkpoint.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--quick", action="store_true", help="Skip the full backend regression while retaining focused gates.")
    mode.add_argument("--ci", action="store_true", help="Run full verification and require a clean checkout after generated/build outputs.")
    parser.add_argument("--list", action="store_true", help="List the verification gates without running them.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.list:
        gates = [
            "Git diff integrity (pre)",
            "Extension dependency audit",
            "Extension TypeScript",
            "Extension production build",
            "Learned local model contract",
            "Perception + visual contract",
            "Python↔browser interoperability",
            "Typed action-plan contract",
            "Browser/privacy regression",
            "Full backend regression (skipped in --quick)",
            "Frontend dependency audit",
            "Frontend TypeScript",
            "Frontend production build",
            "Generated contract determinism",
            "Git diff integrity (final)",
            "CI checkout drift (--ci only)",
        ]
        print("\n".join(f"{idx:02d}. {gate}" for idx, gate in enumerate(gates, 1)))
        return 0
    return Harness(quick=args.quick, ci=args.ci).run()


if __name__ == "__main__":
    raise SystemExit(main())
