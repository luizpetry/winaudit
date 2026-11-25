"""winaudit update: atualiza programas pelo winget.

E o unico comando do WinAudit que altera o PC, e sempre mostra o plano e pede
confirmacao antes. Por padrao atualiza so os programas com CVE conhecida; com
--all, tudo que o winget tiver, menos jogos e launchers de jogos (que se
atualizam pelo proprio launcher).
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys

from . import prog
from .admin import is_admin
from .checks import Context
from .models import Severity, Status
from .report.terminal import BOLD, COLORS, DIM, Printer

# ---------------------------------------------------------------- jogos

# pastas onde launchers instalam jogos
GAME_PATHS = re.compile(
    r"\\steamapps\\|\\steam\\|\\epic games\\|\\riot games\\|\\ubisoft( game launcher)?\\|\\ea games\\|"
    r"\\electronic arts\\|\\rockstar games\\|\\gog galaxy\\|\\gog games\\|\\xboxgames\\|\\battle\.net\\",
    re.I)
GAME_PUBLISHERS = re.compile(
    r"^(valve|riot games|blizzard|electronic arts|ubisoft|rockstar games|epic games|square enix|activision|"
    r"bethesda|cd projekt|hazelight|netease|digital extremes|mojang|roblox|hoyoverse|mihoyo|cognosphere|krafton|"
    r"bandai namco|capcom|sega|2k|take-two|grinding gear|bungie|embark studios|amazon games|ncsoft|wemade|"
    r"garena|paradox interactive|focus entertainment|devolver|gearbox|warner bros\. games|kakao games|"
    r"nexon|smilegate|pearl abyss|gaijin|wargaming|innersloth|re-logic|mediatonic|playtonic)\b",
    re.I)
# prefixo do ID no winget ('EpicGames.EpicGamesLauncher')
GAME_ID_PREFIXES = {"valve", "epicgames", "electronicarts", "ubisoft", "rockstargames", "riotgames", "blizzard",
                    "digitalextremes", "gog", "mojang", "roblox", "cognosphere", "hoyoverse", "squareenix",
                    "bethesda", "cdprojekt", "krafton", "wargaming", "gaijin", "nexon", "garena", "playtonic"}
GAME_NAMES = re.compile(
    r"^(steam|epic games launcher|ea app|ea desktop|origin|battle\.net|ubisoft connect|uplay|"
    r"rockstar games launcher|riot client|gog galaxy|xbox|minecraft launcher|roblox (player|studio))\b",
    re.I)


def is_game(row: dict, app: dict | None) -> bool:
    """Jogo ou launcher de jogos? Usa o ID do winget e, se houver, os dados do registro."""
    prefix = row.get("id", "").split(".", 1)[0].lower()
    if prefix in GAME_ID_PREFIXES or GAME_NAMES.search(row.get("name", "")):
        return True
    if app:
        if re.match(r"^Steam App \d+$", app.get("key", "")):
            return True
        if GAME_PUBLISHERS.search(app.get("publisher", "").strip()):
            return True
        if GAME_PATHS.search(app.get("location", "") + "\\"):
            return True
        if GAME_NAMES.search(app.get("name", "")):
            return True
    return False


# ---------------------------------------------------------------- winget


class WingetError(RuntimeError):
    pass


def parse_winget_table(text: str) -> list[dict]:
    """Le a tabela de 'winget upgrade'. Funciona em qualquer idioma: as colunas sao
    achadas pela posicao das palavras do cabecalho, que fica logo acima da linha de tracos."""
    lines = [ln.split("\r")[-1].rstrip() for ln in text.replace("\r\n", "\n").split("\n")]
    rows = []
    for i, line in enumerate(lines):
        if i == 0 or not re.fullmatch(r"-{20,}", line.strip()):
            continue
        header = lines[i - 1]
        starts = [m.start() for m in re.finditer(r"\S+", header)]
        if len(starts) < 4:
            continue
        # tabela de "pacotes que precisam ser indicados explicitamente" (ex.: fixados)
        before = next((lines[j] for j in range(i - 2, -1, -1) if lines[j].strip()), "")
        explicit = before.rstrip().endswith(":")
        for line in lines[i + 1:]:
            if not line.strip() or len(line) < starts[2]:
                break
            cols = [line[a:b].strip() for a, b in zip(starts, starts[1:] + [len(line)])]
            name, pkg_id, version, available = cols[:4]
            if not pkg_id or " " in pkg_id:
                break  # linha de resumo ('42 atualizacoes disponiveis.')
            rows.append({"name": name, "id": pkg_id, "version": version, "available": available,
                         "source": cols[4] if len(cols) > 4 else "", "explicit": explicit})
    return rows


def winget_upgradable() -> list[dict]:
    try:
        proc = subprocess.run(["winget", "upgrade", "--accept-source-agreements", "--disable-interactivity"],
                              capture_output=True, timeout=300)
    except FileNotFoundError as e:
        raise WingetError("winget nao encontrado. Instale o 'Instalador de Aplicativo' pela Microsoft Store.") from e
    except subprocess.TimeoutExpired as e:
        raise WingetError("winget nao respondeu em 5 minutos") from e
    return parse_winget_table(proc.stdout.decode("utf-8", errors="replace"))


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def find_row(app: dict, rows: list[dict]) -> dict | None:
    """Acha na lista do winget o programa do inventario (o winget usa o mesmo nome do registro)."""
    name = _norm(app["name"])
    for r in rows:
        rn = _norm(r["name"])
        if rn == name or (rn.endswith("…") and name.startswith(rn[:-1])):
            return r
    return None


def _app_for_row(row: dict, apps: list[dict]) -> dict | None:
    return next((a for a in apps if find_row(a, [row])), None)


# ---------------------------------------------------------------- plano


SEV_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.NONE: 4}


def build_plan(rows: list[dict], apps: list[dict], vulnerable: list[dict] | None, include_games: bool):
    """Retorna (atualizar, jogos_pulados, vulneraveis_sem_winget).

    vulnerable=None significa --all: tudo que o winget tiver.
    """
    plan, skipped_games, manual = [], [], []
    if vulnerable is None:
        for r in rows:
            if r["explicit"]:
                continue  # fixados com 'winget pin': o --all do winget tambem pula
            if not include_games and is_game(r, _app_for_row(r, apps)):
                skipped_games.append(r)
                continue
            plan.append((r, None))
        return plan, skipped_games, manual

    seen = set()
    for v in sorted(vulnerable, key=lambda v: (SEV_ORDER[v["severity"]], -v["exploited"])):
        r = find_row(v["app"], rows)
        if not r:
            manual.append(v)
            continue
        if r["id"] in seen:
            continue
        seen.add(r["id"])
        if not include_games and is_game(r, v["app"]):
            skipped_games.append(r)
            continue
        plan.append((r, v))
    return plan, skipped_games, manual


def _reason(v: dict | None) -> str:
    if not v:
        return ""
    text = f"{v['cves']} CVE(s)"
    if v["exploited"]:
        text += f", {v['exploited']} explorada(s)"
    return text


# ---------------------------------------------------------------- comando


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=f"{prog()} update",
        description="Atualiza programas pelo winget. Por padrao, so os que tem vulnerabilidades conhecidas.")
    p.add_argument("--all", action="store_true",
                   help="atualiza tudo que o winget tiver (menos jogos), nao so os vulneraveis")
    p.add_argument("--games", action="store_true", help="inclui jogos e launchers de jogos")
    p.add_argument("--cve-auto", action="store_true",
                   help="usa a descoberta automatica de CVEs para achar mais programas vulneraveis")
    p.add_argument("--dry-run", action="store_true", help="so mostra o que seria atualizado")
    p.add_argument("-y", "--yes", action="store_true", help="nao pede confirmacao")
    p.add_argument("--no-color", action="store_true", help="desativa cores")
    return p


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    pr = Printer(color=not args.no_color)
    from .checks.software import inventory

    print(pr.c(BOLD, "WinAudit update") + pr.c(DIM, "  (usa o winget para instalar as atualizacoes)"))
    apps = inventory()

    vulnerable = None
    if not args.all:
        from .checks.cve import cve as cve_check
        print(pr.c(DIM, "  procurando programas vulneraveis..."))
        ctx = Context(is_admin=is_admin(), enable_cve=True, cve_auto=args.cve_auto, progress=pr.detail)
        ctx.shared["software"] = apps
        cve_check(ctx)
        vulnerable = ctx.shared.get("vulnerable", [])
        if not vulnerable:
            print("\nNenhum programa com vulnerabilidade conhecida. "
                  f"Use '{prog()} update --all' para atualizar o resto mesmo assim.")
            return 0

    print(pr.c(DIM, "  consultando atualizacoes no winget..."))
    try:
        rows = winget_upgradable()
    except WingetError as e:
        print(f"\n{e}", file=sys.stderr)
        return 2

    plan, games, manual = build_plan(rows, apps, vulnerable, args.games)

    if plan:
        print(pr.c(BOLD, f"\nVai atualizar {len(plan)} programa(s):"))
        width = max(len(r["name"]) for r, _ in plan)
        for r, v in plan:
            why = _reason(v)
            color = COLORS[Status.FAIL] if v and v["exploited"] else ""
            print(f"  {r['name']:<{width}}  {r['version']} -> {r['available']}"
                  + (pr.c(color, f"  ({why})") if why and color else pr.c(DIM, f"  ({why})") if why else ""))
    if games:
        print(pr.c(DIM, f"\n{len(games)} jogo(s)/launcher(s) ficaram de fora (atualize pelo launcher, "
                        "ou use --games): " + ", ".join(r["name"] for r in games)))
    if manual:
        print(pr.c(BOLD, f"\n{len(manual)} programa(s) vulneravel(is) sem atualizacao pelo winget:"))
        for v in manual:
            print(f"  {v['label']}  ({_reason(v)})")
            print(pr.c(DIM, f"    se nao usa, desinstale: winget uninstall \"{v['app']['name']}\""))
        print(pr.c(DIM, "  Se usa, atualize pelo proprio programa ou pelo site oficial."))
    if not plan:
        print("\nNada para atualizar pelo winget.")
        return 0 if not manual else 1
    if args.dry_run:
        print(pr.c(DIM, "\n--dry-run: nada foi instalado."))
        return 0

    if not args.yes:
        if not sys.stdin.isatty():
            print("\nSem terminal interativo para confirmar. Rode de novo com -y para atualizar.", file=sys.stderr)
            return 2
        answer = input(f"\nAtualizar {len(plan)} programa(s)? Feche-os antes. [s/N] ").strip().lower()
        if answer not in ("s", "sim", "y", "yes"):
            print("Cancelado.")
            return 0

    failed = []
    for i, (r, _) in enumerate(plan, 1):
        print(pr.c(BOLD, f"\n[{i}/{len(plan)}] {r['name']}  {r['version']} -> {r['available']}"))
        code = subprocess.call(["winget", "upgrade", "--id", r["id"], "--exact",
                                "--accept-source-agreements", "--accept-package-agreements"])
        if code != 0:
            failed.append(r["name"])

    ok = len(plan) - len(failed)
    print(pr.c(BOLD, f"\n{ok} de {len(plan)} programa(s) atualizado(s)."))
    if failed:
        print(pr.c(COLORS[Status.FAIL], "Falharam: " + ", ".join(failed)))
        print(pr.c(DIM, "Feche esses programas e tente de novo, ou atualize pelo site oficial."))
    print(pr.c(DIM, f"Rode '{prog()} --cve --html relatorio.html' de novo para ver a nota nova."))
    return 1 if failed or manual else 0
