"""Executa os checks registrados."""
from __future__ import annotations

import time
from typing import Callable

from .checks import CheckDef, Context, load_all
from .models import CheckResult, info


def run_checks(ctx: Context, on_progress: Callable[[str], None] | None = None,
               only: set[str] | None = None) -> list[CheckResult]:
    results: list[CheckResult] = []
    for cd in load_all():
        if cd.optional and not _optional_enabled(cd, ctx):
            continue
        if only and cd.name not in only:
            continue
        if on_progress:
            on_progress(cd.name)
        results.append(_run_one(cd, ctx))
    return results


def _optional_enabled(cd: CheckDef, ctx: Context) -> bool:
    return cd.name == "cve" and ctx.enable_cve


def _run_one(cd: CheckDef, ctx: Context) -> CheckResult:
    start = time.perf_counter()
    try:
        findings = cd.fn(ctx) or []
        error = None
    except Exception as e:  # um check com erro nao derruba os outros
        error = f"{type(e).__name__}: {e}"
        findings = [info(f"{cd.name}.error", f"Nao foi possivel verificar ({cd.name})", error)]
    ms = int((time.perf_counter() - start) * 1000)
    return CheckResult(cd.name, cd.category, findings, ms, error)
