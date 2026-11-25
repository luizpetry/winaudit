from ..models import Severity, failed, passed, warn
from ..reg import read_value
from . import check

KEY = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"


@check("uac", "Sistema", order=30)
def uac(ctx):
    findings = []
    if read_value(KEY, "EnableLUA", 1) != 1:
        findings.append(failed("uac.enabled", "UAC desativado", Severity.HIGH,
                               "Todo programa roda com privilegios totais sem pedir confirmacao.",
                               "Painel de Controle > Contas de Usuario > Alterar configuracoes de Controle de Conta de Usuario (requer reinicio)."))
        return findings
    findings.append(passed("uac.enabled", "UAC ativado"))

    consent = read_value(KEY, "ConsentPromptBehaviorAdmin", 5)
    if consent == 0:
        findings.append(failed("uac.prompt", "UAC eleva sem perguntar", Severity.HIGH,
                               "Administradores sao elevados silenciosamente (ConsentPromptBehaviorAdmin=0).",
                               "Suba o controle deslizante do UAC para pelo menos o nivel padrao."))
    elif read_value(KEY, "PromptOnSecureDesktop", 1) == 0:
        findings.append(warn("uac.securedesktop", "Prompt do UAC fora da area de trabalho segura", Severity.LOW,
                             "Outros programas podem interagir com a janela de confirmacao.",
                             "Use o nivel padrao do UAC (que escurece a tela)."))
    else:
        findings.append(passed("uac.prompt", "UAC pede confirmacao"))
    return findings
