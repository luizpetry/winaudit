from ..models import Severity, failed, info, passed, warn
from ..ps import PSError, as_list, run_ps
from . import check

MP_CMD = (
    "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,"
    "RealTimeProtectionEnabled,AntivirusSignatureAge,IsTamperProtected,AMRunningMode"
)
AV_CMD = (
    "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
    "Select-Object displayName,productState"
)


def _third_party_av() -> list[str]:
    try:
        products = as_list(run_ps(AV_CMD))
    except PSError:
        return []
    return [p["displayName"] for p in products
            if p.get("displayName") and "defender" not in p["displayName"].lower()]


@check("defender", "Antivirus", order=20)
def defender(ctx):
    try:
        st = run_ps(MP_CMD) or {}
    except PSError as e:
        others = _third_party_av()
        if others:
            return [info("defender.thirdparty", "Antivirus de terceiros detectado",
                         "Defender indisponivel; outro antivirus esta registrado.", others)]
        return [failed("defender.unavailable", "Nenhum antivirus detectado", Severity.CRITICAL,
                       f"Nao foi possivel consultar o Defender ({e}) e nenhum outro antivirus foi encontrado.",
                       "Ative o Microsoft Defender em Seguranca do Windows > Protecao contra virus e ameacas.")]

    mode = str(st.get("AMRunningMode", ""))
    if mode.lower() in ("passive mode", "passive", "edr block mode"):
        others = _third_party_av()
        return [info("defender.passive", "Defender em modo passivo",
                     "Outro antivirus esta fazendo a protecao principal.", others)]

    findings = []
    if not st.get("AntivirusEnabled") or not st.get("AMServiceEnabled"):
        findings.append(failed("defender.enabled", "Antivirus desativado", Severity.CRITICAL,
                               "O servico antimalware do Defender nao esta ativo.",
                               "Seguranca do Windows > Protecao contra virus e ameacas > Ativar."))
    else:
        findings.append(passed("defender.enabled", "Antivirus ativo"))

    if not st.get("RealTimeProtectionEnabled"):
        findings.append(failed("defender.realtime", "Protecao em tempo real desligada", Severity.HIGH,
                               "Arquivos nao sao verificados ao serem abertos ou baixados.",
                               "Set-MpPreference -DisableRealtimeMonitoring $false   (como admin)"))
    else:
        findings.append(passed("defender.realtime", "Protecao em tempo real ligada"))

    age = st.get("AntivirusSignatureAge")
    if isinstance(age, int) and age > 7:
        findings.append(failed("defender.signatures", "Assinaturas do antivirus desatualizadas", Severity.HIGH,
                               f"Ultima atualizacao de definicoes ha {age} dias.",
                               "Update-MpSignature"))
    elif isinstance(age, int) and age > 3:
        findings.append(warn("defender.signatures", "Assinaturas com alguns dias", Severity.LOW,
                             f"Ultima atualizacao de definicoes ha {age} dias.", "Update-MpSignature"))
    else:
        findings.append(passed("defender.signatures", "Assinaturas atualizadas",
                               f"Idade: {age} dia(s)." if age is not None else ""))

    if st.get("IsTamperProtected") is False:
        findings.append(warn("defender.tamper", "Protecao contra violacao desligada", Severity.MEDIUM,
                             "Malware com privilegio pode desligar o Defender sem aviso.",
                             "Seguranca do Windows > Protecao contra virus e ameacas > Gerenciar configuracoes > Protecao contra violacao."))
    elif st.get("IsTamperProtected"):
        findings.append(passed("defender.tamper", "Protecao contra violacao ligada"))
    return findings
