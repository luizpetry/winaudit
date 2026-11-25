from ..models import Severity, failed, passed, warn
from ..ps import as_list, run_ps
from . import check

CMD = (
    "Get-NetFirewallProfile | Select-Object Name,"
    "@{n='Enabled';e={$_.Enabled.ToString()}},"
    "@{n='DefaultInboundAction';e={$_.DefaultInboundAction.ToString()}}"
)


@check("firewall", "Rede", order=10)
def firewall(ctx):
    profiles = as_list(run_ps(CMD))
    findings = []
    for p in profiles:
        name = p.get("Name", "?")
        enabled = p.get("Enabled") in ("True", "NotConfigured")  # NotConfigured => padrao ligado
        inbound = p.get("DefaultInboundAction", "")
        fid = f"firewall.{name.lower()}"
        if not enabled:
            sev = Severity.HIGH if name == "Public" else Severity.MEDIUM
            findings.append(failed(
                fid, f"Firewall desativado no perfil {name}", sev,
                f"O Firewall do Windows esta desligado para redes do tipo {name}.",
                f"Set-NetFirewallProfile -Profile {name} -Enabled True   (como admin)"))
        elif inbound == "Allow":
            findings.append(warn(
                fid, f"Perfil {name} permite entrada por padrao", Severity.MEDIUM,
                "Conexoes de entrada sao aceitas a menos que uma regra bloqueie.",
                f"Set-NetFirewallProfile -Profile {name} -DefaultInboundAction Block"))
        else:
            findings.append(passed(fid, f"Firewall ativo no perfil {name}"))
    return findings
