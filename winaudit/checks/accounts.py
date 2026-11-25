import getpass

from ..models import Severity, failed, info, passed, warn
from ..ps import PSError, as_list, run_ps
from . import check

USERS_CMD = (
    "Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,"
    "@{n='PasswordExpires';e={if ($_.PasswordExpires) {$_.PasswordExpires.ToString('yyyy-MM-dd')} else {$null}}},"
    "@{n='Sid';e={$_.SID.Value}}"
)
# SID do grupo Administradores e o mesmo em qualquer idioma do Windows
ADMINS_CMD = (
    "Get-LocalGroupMember -SID 'S-1-5-32-544' | Select-Object Name,ObjectClass,PrincipalSource"
)


@check("accounts", "Contas", order=50)
def accounts(ctx):
    findings = []
    users = as_list(run_ps(USERS_CMD))
    enabled = [u for u in users if u.get("Enabled")]

    guest = next((u for u in users if str(u.get("Sid", "")).endswith("-501")), None)
    if guest and guest.get("Enabled"):
        findings.append(failed("accounts.guest", "Conta Convidado ativa", Severity.HIGH,
                               f"A conta '{guest['Name']}' permite acesso sem identificacao.",
                               f"Disable-LocalUser -Name '{guest['Name']}'   (como admin)"))
    else:
        findings.append(passed("accounts.guest", "Conta Convidado desativada"))

    builtin = next((u for u in users if str(u.get("Sid", "")).endswith("-500")), None)
    if builtin and builtin.get("Enabled"):
        findings.append(warn("accounts.builtin_admin", "Administrador interno ativo", Severity.MEDIUM,
                             f"A conta '{builtin['Name']}' e alvo conhecido de ataques de senha e nao tem bloqueio por tentativas.",
                             f"Disable-LocalUser -Name '{builtin['Name']}'   (como admin)"))

    no_pwd = [u["Name"] for u in enabled if u.get("PasswordRequired") is False]
    if no_pwd:
        # O Windows marca assim contas criadas na instalacao/contas Microsoft mesmo com senha,
        # entao isso sozinho nao prova nada: so informa.
        findings.append(info("accounts.nopassword", "Contas com 'senha nao obrigatoria'",
                             "Comum em contas criadas na instalacao do Windows, mesmo que tenham senha. "
                             "Confirme que cada uma tem senha (ou PIN/Windows Hello) e, se quiser, rode como admin: "
                             "net user <nome> /passwordreq:yes",
                             no_pwd))

    try:
        admins = as_list(run_ps(ADMINS_CMD))
    except PSError as e:
        findings.append(info("accounts.admins", "Nao foi possivel listar administradores", str(e)))
        return findings

    names = [a.get("Name", "?") for a in admins]
    if len(admins) > 2:
        findings.append(warn("accounts.admins", f"{len(admins)} membros no grupo Administradores", Severity.LOW,
                             "Cada conta admin e uma porta a mais com controle total da maquina.",
                             "Remova quem nao precisa: Remove-LocalGroupMember -SID S-1-5-32-544 -Member <nome>",
                             names))
    else:
        findings.append(info("accounts.admins", "Membros do grupo Administradores", evidence=names))

    me = getpass.getuser().lower()
    if any(n.lower().split("\\")[-1] == me for n in names):
        findings.append(warn("accounts.daily_admin", "Voce usa uma conta de administrador no dia a dia", Severity.LOW,
                             "Malware executado na sua sessao herda privilegios de admin assim que o UAC for aceito.",
                             "Crie uma conta padrao para o uso diario e use a de admin so para instalar e configurar."))
    return findings
