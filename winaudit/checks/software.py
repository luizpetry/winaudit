import re

from ..models import Severity, info, warn
from ..reg import list_subkeys, read_value
from . import check

UNINSTALL = [
    (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", True),
    (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", False),
    (r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", True),
]

# software sem suporte do fabricante: nao recebe mais correcoes de seguranca
END_OF_LIFE = [
    (re.compile(r"adobe flash", re.I), "Adobe Flash Player (sem suporte desde 2020)"),
    (re.compile(r"silverlight", re.I), "Microsoft Silverlight (sem suporte desde 2021)"),
    (re.compile(r"^python 2\.", re.I), "Python 2 (sem suporte desde 2020)"),
    (re.compile(r"java.*\b(6|7)\b.*update|^java\(tm\) (6|7)", re.I), "Java 6/7 (sem suporte)"),
    (re.compile(r"quicktime", re.I), "QuickTime para Windows (sem suporte desde 2016)"),
    (re.compile(r"adobe shockwave", re.I), "Adobe Shockwave (sem suporte desde 2019)"),
    (re.compile(r"internet explorer", re.I), "Internet Explorer (sem suporte desde 2022)"),
]


def inventory() -> list[dict]:
    seen = set()
    apps = []
    for base, view64 in UNINSTALL:
        for sub in list_subkeys(base, view64=view64):
            path = f"{base}\\{sub}"
            name = read_value(path, "DisplayName", view64=view64)
            if not name or read_value(path, "SystemComponent", 0, view64=view64) == 1:
                continue
            version = str(read_value(path, "DisplayVersion", "", view64=view64) or "")
            key = (name.strip().lower(), version)
            if key in seen:
                continue
            seen.add(key)
            apps.append({
                "name": name.strip(),
                "version": version,
                "publisher": str(read_value(path, "Publisher", "", view64=view64) or ""),
                # usados para reconhecer jogos (ex.: chave 'Steam App 730', pasta steamapps)
                "key": sub,
                "location": str(read_value(path, "InstallLocation", "", view64=view64) or ""),
            })
    return sorted(apps, key=lambda a: a["name"].lower())


@check("software", "Software", order=100)
def software(ctx):
    apps = inventory()
    ctx.shared["software"] = apps
    findings = []
    eol = []
    for a in apps:
        for rx, label in END_OF_LIFE:
            if rx.search(a["name"]):
                eol.append(f"{a['name']} {a['version']}".strip() + f": {label}")
                break
    if eol:
        findings.append(warn("software.eol", f"{len(eol)} programa(s) sem suporte do fabricante", Severity.MEDIUM,
                             "Esses programas nao recebem mais correcoes de seguranca.",
                             "Desinstale em Configuracoes > Aplicativos, ou troque por uma versao suportada.", eol))
    findings.append(info("software.inventory", f"{len(apps)} programas instalados",
                         "" if ctx.enable_cve else "Use --cve para procurar vulnerabilidades conhecidas nos mais comuns, "
                         "ou --cve-auto para tentar em todos.",
                         [f"{a['name']} {a['version']}".strip() for a in apps]))
    return findings
