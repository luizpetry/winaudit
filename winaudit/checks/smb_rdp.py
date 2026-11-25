from ..models import Severity, failed, passed, warn
from ..ps import PSError, run_ps
from ..reg import read_value
from . import check

TS_KEY = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"
RDP_TCP = TS_KEY + r"\WinStations\RDP-Tcp"
SMB_PARAMS = r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
SMB1_CLIENT = r"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10"


def _smb1_enabled() -> bool | None:
    try:
        r = run_ps("Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol")
        if isinstance(r, dict) and "EnableSMB1Protocol" in r:
            return bool(r["EnableSMB1Protocol"])
    except PSError:
        pass
    # fallback pelo registro: valor explicito no servidor ou driver cliente habilitado
    v = read_value(SMB_PARAMS, "SMB1")
    if v is not None:
        return v != 0
    start = read_value(SMB1_CLIENT, "Start")
    if start is None:
        return False  # driver nem instalado
    return start != 4  # 4 = desabilitado


@check("smb_rdp", "Rede", order=40)
def smb_rdp(ctx):
    findings = []

    smb1 = _smb1_enabled()
    if smb1:
        findings.append(failed("smb.v1", "SMBv1 habilitado", Severity.HIGH,
                               "Protocolo obsoleto explorado pelo WannaCry (EternalBlue).",
                               "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol   (como admin)"))
    else:
        findings.append(passed("smb.v1", "SMBv1 desabilitado"))

    rdp_on = read_value(TS_KEY, "fDenyTSConnections", 1) == 0
    if not rdp_on:
        findings.append(passed("rdp.enabled", "Area de Trabalho Remota desligada"))
    else:
        nla = read_value(RDP_TCP, "UserAuthentication", 1) == 1
        if not nla:
            findings.append(failed("rdp.nla", "RDP ligado sem NLA", Severity.HIGH,
                                   "A Area de Trabalho Remota aceita conexoes antes de autenticar o usuario.",
                                   "Configuracoes > Sistema > Area de Trabalho Remota > Configuracoes avancadas > Exigir NLA."))
        else:
            findings.append(warn("rdp.enabled", "Area de Trabalho Remota ligada", Severity.LOW,
                                 "RDP esta ativo (com NLA). Se nao usa, desligue para reduzir a superficie de ataque.",
                                 "Configuracoes > Sistema > Area de Trabalho Remota > Desativar."))
    return findings
