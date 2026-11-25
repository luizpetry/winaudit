"""Interface de linha de comando do WinAudit."""
from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import datetime
from pathlib import Path

from . import __version__, prog
from .admin import is_admin
from .checks import Context, load_all
from .report import html as html_report
from .report.terminal import Printer
from .runner import run_checks
from .scoring import compute_score, grade


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=prog(),
                                description="Auditoria de seguranca do Windows (somente leitura).",
                                epilog=f"Para atualizar os programas vulneraveis pelo winget: {prog()} update "
                                       f"(veja '{prog()} update --help').")
    p.add_argument("--html", metavar="ARQUIVO", help="gera relatorio HTML neste arquivo")
    p.add_argument("--json", metavar="ARQUIVO", nargs="?", const="-",
                   help="saida JSON (em arquivo, ou no terminal se omitido)")
    p.add_argument("--cve", action="store_true",
                   help="consulta CVEs conhecidas no NVD (envia apenas nome/versao de programas comuns)")
    p.add_argument("--cve-auto", action="store_true",
                   help="como --cve, mas tenta identificar tambem os demais programas instalados "
                        "(envia o nome deles ao NVD; mais lento)")
    p.add_argument("--only", metavar="CHECKS", help="roda so estes checks, separados por virgula")
    p.add_argument("--list", action="store_true", help="lista os checks disponiveis")
    p.add_argument("--no-color", action="store_true", help="desativa cores")
    p.add_argument("-v", "--verbose", action="store_true", help="mostra todos os detalhes")
    p.add_argument("--version", action="version", version=f"winaudit {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if platform.system() != "Windows":
        print("O WinAudit so funciona no Windows.", file=sys.stderr)
        return 2
    if argv[:1] == ["update"]:
        from .update import main as update_main
        return update_main(argv[1:])
    args = build_parser().parse_args(argv)

    if args.list:
        for cd in load_all():
            print(f"  {cd.name:<10} {cd.category}" + ("  (opcional: --cve)" if cd.optional else ""))
        return 0

    json_stdout = args.json == "-"
    printer = Printer(color=not args.no_color, verbose=args.verbose)
    admin = is_admin()
    ctx = Context(is_admin=admin, enable_cve=args.cve or args.cve_auto, cve_auto=args.cve_auto)
    if not json_stdout:
        ctx.progress = printer.detail
    only = {s.strip() for s in args.only.split(",")} if args.only else None
    if only and "cve" in only:
        ctx.enable_cve = True

    if not json_stdout:
        print(printer.c("\033[1m", f"WinAudit {__version__}") +
              ("" if admin else printer.c("\033[2m", "  (sem admin: alguns checks ficam limitados)")))
    results = run_checks(ctx, on_progress=None if json_stdout else printer.progress, only=only)
    score = compute_score(results)
    g = grade(score)

    if args.json:
        payload = {
            "version": __version__,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "host": platform.node(),
            "is_admin": admin,
            "score": score,
            "grade": g,
            "results": [r.to_dict() for r in results],
        }
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        if json_stdout:
            print(text)
        else:
            Path(args.json).write_text(text, encoding="utf-8")

    if not json_stdout:
        printer.results(results, score, g, admin)

    if args.html:
        out = Path(args.html)
        out.write_text(html_report.render(results, score, g, admin), encoding="utf-8")
        if not json_stdout:
            print(f"\nRelatorio HTML salvo em {out.resolve()}")
    if args.json and not json_stdout:
        print(f"JSON salvo em {Path(args.json).resolve()}")

    # codigo de saida util para automacao: 1 se houver falhas
    return 1 if any(f.status.value == "FAIL" for r in results for f in r.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
