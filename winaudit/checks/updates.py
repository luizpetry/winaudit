from datetime import date, datetime

from ..models import Severity, failed, info, passed, warn
from ..ps import PSError, as_list, run_ps
from . import check

HOTFIX_CMD = (
    "Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | "
    "Select-Object -First 1 HotFixID,@{n='InstalledOn';e={$_.InstalledOn.ToString('yyyy-MM-dd')}}"
)
PENDING_CMD = (
    "$s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher();"
    "$r = $s.Search(\"IsInstalled=0 and Type='Software' and IsHidden=0\");"
    "$r.Updates | ForEach-Object { [pscustomobject]@{ Title=$_.Title; "
    "Severity=$_.MsrcSeverity; Security=[bool]($_.Categories | Where-Object { $_.Name -match 'Security|Seguran' }) } }"
)
BUILD_CMD = (
    "$v = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion';"
    "[pscustomobject]@{ Product=$v.ProductName; Display=$v.DisplayVersion; Build=\"$($v.CurrentBuild).$($v.UBR)\" }"
)


@check("updates", "Atualizacoes", order=80)
def updates(ctx):
    findings = []

    try:
        b = run_ps(BUILD_CMD) or {}
        findings.append(info("updates.build", "Versao do Windows",
                             f"{b.get('Product')} {b.get('Display') or ''} (build {b.get('Build')})"))
    except PSError:
        pass

    try:
        hf = run_ps(HOTFIX_CMD)
    except PSError:
        hf = None
    if hf and hf.get("InstalledOn"):
        last = datetime.strptime(hf["InstalledOn"], "%Y-%m-%d").date()
        days = (date.today() - last).days
        detail = f"Ultima atualizacao instalada: {hf['HotFixID']} em {last:%d/%m/%Y} (ha {days} dias)."
        if days > 60:
            findings.append(failed("updates.age", "Windows sem atualizar ha mais de 2 meses", Severity.HIGH, detail,
                                   "Configuracoes > Windows Update > Verificar atualizacoes."))
        elif days > 35:
            findings.append(warn("updates.age", "Windows perdeu o ultimo ciclo de atualizacoes", Severity.MEDIUM, detail,
                                 "Configuracoes > Windows Update > Verificar atualizacoes."))
        else:
            findings.append(passed("updates.age", "Atualizacoes recentes instaladas", detail))

    try:
        pending = as_list(run_ps(PENDING_CMD, timeout=240))
    except PSError as e:
        findings.append(info("updates.pending", "Nao foi possivel consultar atualizacoes pendentes", str(e)))
        return findings

    titles = [p.get("Title", "?") for p in pending]
    critical = [p for p in pending if (p.get("Severity") or "").lower() == "critical"]
    security = [p for p in pending if p.get("Security") or p.get("Severity")]
    if critical:
        findings.append(failed("updates.pending", f"{len(critical)} atualizacao(oes) critica(s) pendente(s)", Severity.HIGH,
                               "Correcoes de seguranca criticas aguardando instalacao.",
                               "Configuracoes > Windows Update > Instalar agora, e reinicie.", titles))
    elif security:
        findings.append(warn("updates.pending", f"{len(security)} atualizacao(oes) de seguranca pendente(s)", Severity.MEDIUM,
                             "Ha correcoes de seguranca esperando instalacao.",
                             "Configuracoes > Windows Update > Instalar agora.", titles))
    elif pending:
        findings.append(info("updates.pending", f"{len(pending)} atualizacao(oes) opcional(is) disponivel(is)", evidence=titles))
    else:
        findings.append(passed("updates.pending", "Nenhuma atualizacao pendente"))
    return findings
