"""Saida colorida no terminal."""
from __future__ import annotations

import os
import sys

from ..models import CheckResult, Status

COLORS = {
    Status.PASS: "\033[32m",
    Status.WARN: "\033[33m",
    Status.FAIL: "\033[31m",
    Status.INFO: "\033[36m",
}
ICONS = {Status.PASS: "OK  ", Status.WARN: "WARN", Status.FAIL: "FAIL", Status.INFO: "INFO"}
DIM, BOLD, RESET = "\033[2m", "\033[1m", "\033[0m"


class Printer:
    def __init__(self, color: bool = True, verbose: bool = False):
        self.color = color and sys.stdout.isatty()
        self.verbose = verbose
        if self.color and os.name == "nt":
            os.system("")  # habilita sequencias ANSI no console do Windows
        # evita erro de encoding em consoles cp1252/cp850
        try:
            sys.stdout.reconfigure(errors="replace")
        except Exception:
            pass

    def c(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self.color else text

    def progress(self, name: str):
        sys.stdout.write(self.c(DIM, f"  verificando {name}...") + "\n")
        sys.stdout.flush()

    def detail(self, msg: str):
        sys.stdout.write(self.c(DIM, f"    {msg}") + "\n")
        sys.stdout.flush()

    def results(self, results: list[CheckResult], score: int, grade: str, is_admin: bool):
        print()
        current = None
        for r in sorted(results, key=lambda r: r.category):
            if r.category != current:
                current = r.category
                print(self.c(BOLD, f"\n== {current} =="))
            for f in r.findings:
                tag = self.c(COLORS[f.status], f"[{ICONS[f.status]}]")
                sev = f" ({f.severity.value})" if f.status in (Status.FAIL, Status.WARN) else ""
                print(f"  {tag} {f.title}{self.c(DIM, sev)}")
                if f.status in (Status.FAIL, Status.WARN):
                    if f.details:
                        print(f"         {f.details}")
                    if f.risks:
                        print(self.c(BOLD, "         Riscos de manter assim:"))
                        for risk in f.risks:
                            print(f"           * {risk}")
                    if f.remediation:
                        print(self.c(DIM, "         Como corrigir: ") + f.remediation)
                    for e in f.evidence[:5]:
                        print(self.c(DIM, f"           - {e}"))
                    if len(f.evidence) > 5:
                        print(self.c(DIM, f"           ... e mais {len(f.evidence) - 5}"))
                elif self.verbose or f.status == Status.INFO and f.details and len(f.evidence) == 0:
                    if f.details:
                        print(self.c(DIM, f"         {f.details}"))
                    if self.verbose:
                        for e in f.evidence:
                            print(self.c(DIM, f"           - {e}"))
                elif f.evidence and f.status == Status.INFO:
                    print(self.c(DIM, f"         {len(f.evidence)} item(ns), veja o relatorio HTML ou use -v"))

        counts = {s: sum(1 for r in results for f in r.findings if f.status == s) for s in Status}
        color = COLORS[Status.PASS] if score >= 80 else COLORS[Status.WARN] if score >= 60 else COLORS[Status.FAIL]
        print()
        print(self.c(BOLD, "Nota de seguranca: ") + self.c(BOLD + color, f"{score}/100 ({grade})"))
        print(f"  {counts[Status.FAIL]} falha(s), {counts[Status.WARN]} alerta(s), "
              f"{counts[Status.PASS]} ok, {counts[Status.INFO]} informativo(s)")
        if not is_admin:
            print(self.c(COLORS[Status.WARN], "  Dica: rode como administrador para uma verificacao mais completa."))
