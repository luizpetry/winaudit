import os
import re

from ..models import Severity, failed, info, passed, warn
from ..ps import PSError, as_list, run_ps
from ..reg import list_values
from . import check

RUN_KEYS = [
    (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", True),
    (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", True),
    (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", False),  # visao 32 bits (WOW6432Node)
    (r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", True),
    (r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", True),
]

# API COM do Agendador: funciona sem admin (Get-ScheduledTask/CIM e negado).
# Pastas sem permissao sao puladas individualmente. Estado 1 = desabilitada.
TASKS_CMD = r"""
$svc = New-Object -ComObject Schedule.Service; $svc.Connect()
$out = New-Object System.Collections.ArrayList
function Walk($f) {
  if ($f.Path -like '\Microsoft*') { return }
  try { foreach ($t in $f.GetTasks(1)) {
    $acts = @()
    try { foreach ($a in $t.Definition.Actions) { if ($a.Type -eq 0) { $acts += ($a.Path + ' ' + $a.Arguments).Trim() } } } catch {}
    [void]$out.Add([pscustomobject]@{ TaskName=$t.Name; TaskPath=$f.Path; State=$(if ($t.State -eq 1) {'Disabled'} else {'Enabled'}); Actions=($acts -join ' ; ') })
  } } catch {}
  try { foreach ($sub in $f.GetFolders(0)) { Walk $sub } } catch {}
}
Walk ($svc.GetFolder('\'))
$out
"""

# Padroes classicos de persistencia de malware
DANGEROUS = [
    (re.compile(r"-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", re.I), "PowerShell com comando codificado (base64)"),
    (re.compile(r"(iex|invoke-expression).*(downloadstring|iwr|invoke-webrequest)", re.I), "PowerShell baixando e executando codigo"),
    (re.compile(r"\bmshta(\.exe)?\b.*(http|javascript:|vbscript:)", re.I), "mshta executando script remoto"),
    (re.compile(r"\b(regsvr32)(\.exe)?\b.*/i:\s*http", re.I), "regsvr32 carregando script remoto (Squiblydoo)"),
    (re.compile(r"\b(certutil)(\.exe)?\b.*-urlcache", re.I), "certutil usado para baixar arquivo"),
    (re.compile(r"\b[wc]script(\.exe)?\b.*\.(vbs|js|jse|vbe)\b.*(temp|appdata|public)", re.I), "script VBS/JS em pasta temporaria"),
]
SUSPICIOUS_DIRS = re.compile(r"(\\temp\\|\\tmp\\|\\users\\public\\|\\downloads\\|\\appdata\\local\\temp\\|\\recycle)", re.I)


def classify(command: str):
    """Retorna (severity, motivo) ou None se nada suspeito."""
    for rx, why in DANGEROUS:
        if rx.search(command):
            return Severity.HIGH, why
    expanded = os.path.expandvars(command)
    if SUSPICIOUS_DIRS.search(expanded):
        return Severity.MEDIUM, "executavel em pasta temporaria/publica"
    return None


def collect_entries(include_tasks: bool = True) -> list[tuple[str, str, str]]:
    """Lista (origem, nome, comando) de tudo que inicia automaticamente."""
    entries = []
    for key, view64 in RUN_KEYS:
        label = key.replace(r"\SOFTWARE\Microsoft\Windows\CurrentVersion", "") + ("" if view64 else " (32-bit)")
        for name, value in list_values(key, view64=view64):
            if name:
                entries.append((label, name, str(value)))

    for folder in (os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
                   os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp")):
        if os.path.isdir(folder):
            for f in os.listdir(folder):
                if f.lower() != "desktop.ini":
                    entries.append(("Pasta Inicializar", f, os.path.join(folder, f)))

    if include_tasks:
        for t in as_list(run_ps(TASKS_CMD, timeout=90)):
            if t.get("State") == "Disabled":
                continue
            entries.append(("Tarefa agendada", t.get("TaskPath", "") + t.get("TaskName", ""), t.get("Actions") or ""))
    return entries


@check("startup", "Persistencia", order=70)
def startup(ctx):
    findings = []
    try:
        entries = collect_entries()
    except PSError as e:
        entries = collect_entries(include_tasks=False)
        findings.append(info("startup.tasks", "Tarefas agendadas nao verificadas", str(e)))

    flagged = 0
    for origin, name, cmd in entries:
        hit = classify(cmd)
        if not hit:
            continue
        sev, why = hit
        flagged += 1
        make = failed if sev == Severity.HIGH else warn
        findings.append(make(f"startup.{flagged}", f"Inicializacao suspeita: {name}", sev,
                             f"{why}. Origem: {origin}.",
                             "Confira o comando abaixo. Se nao reconhece, desative pelo Gerenciador de Tarefas > "
                             "Inicializar (ou Agendador de Tarefas) e faca uma verificacao completa no antivirus.",
                             [cmd[:300]]))
    # sem comando visivel (oculto sem admin, ou tarefa so com acao COM) nao foi realmente analisado
    hidden = [n for o, n, c in entries if o == "Tarefa agendada" and not c]
    analyzed = len(entries) - len(hidden)
    if not flagged:
        detail = f"{analyzed} item(ns) analisado(s)."
        if hidden:
            detail += (f" {len(hidden)} tarefa(s) agendada(s) ficaram de fora porque o comando nao esta visivel"
                       + (" (rode como admin)." if not ctx.is_admin else "."))
        findings.append(passed("startup.clean", "Nenhum item de inicializacao suspeito", detail))
    if hidden and not ctx.is_admin:
        findings.append(info("startup.tasks_hidden", f"Comandos de {len(hidden)} tarefa(s) agendada(s) ocultos",
                             "O Windows so mostra o que cada tarefa executa para administradores. "
                             "Rode como admin para que esses comandos tambem sejam analisados.", hidden))
    findings.append(info("startup.list", f"{len(entries)} programa(s) iniciam automaticamente",
                         "Lista completa para conferencia.",
                         [f"[{o}] {n}: {c[:160]}" for o, n, c in entries]))
    return findings
