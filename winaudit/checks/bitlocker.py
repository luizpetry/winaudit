import os

import psutil

from ..models import Severity, failed, info, passed, warn
from ..ps import PSError, run_ps
from . import check

ADMIN_CMD = (
    "Get-BitLockerVolume -MountPoint $env:SystemDrive | Select-Object "
    "@{n='Protection';e={$_.ProtectionStatus.ToString()}},"
    "@{n='Volume';e={$_.VolumeStatus.ToString()}},EncryptionPercentage"
)
# Funciona sem admin: propriedade do Shell
SHELL_CMD = (
    "(New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive + '\\').Self"
    ".ExtendedProperty('System.Volume.BitLockerProtection')"
)
# 1=ligado, 2=desligado, 3=criptografando, 4=descriptografando, 5=suspenso, 6=ligado (desbloqueado)
SHELL_STATES = {1: "on", 2: "off", 3: "encrypting", 4: "decrypting", 5: "suspended", 6: "on"}


def _state(ctx) -> str | None:
    if ctx.is_admin:
        try:
            r = run_ps(ADMIN_CMD) or {}
            if r.get("Protection") == "On":
                return "on"
            vol = r.get("Volume", "")
            if vol == "EncryptionInProgress":
                return "encrypting"
            if vol == "FullyEncrypted":
                return "suspended"  # criptografado mas protecao desligada
            return "off"
        except PSError:
            pass
    try:
        v = run_ps(SHELL_CMD)
    except PSError:
        return None
    return SHELL_STATES.get(v) if isinstance(v, int) else None


def _is_laptop() -> bool:
    try:
        return psutil.sensors_battery() is not None
    except Exception:
        return False


@check("bitlocker", "Dados", order=90)
def bitlocker(ctx):
    drive = os.environ.get("SystemDrive", "C:")
    state = _state(ctx)
    laptop = _is_laptop()
    sev = Severity.HIGH if laptop else Severity.MEDIUM
    risk = "Se o notebook for perdido ou roubado" if laptop else "Se alguem tiver acesso fisico ao disco"
    fix = ("Configuracoes > Privacidade e seguranca > Criptografia do dispositivo, ou "
           "Painel de Controle > Criptografia de Unidade de Disco BitLocker. "
           "No Windows Home sem criptografia de dispositivo, considere o VeraCrypt.")

    if state in ("on", "encrypting"):
        return [passed("bitlocker", f"Disco do sistema ({drive}) criptografado",
                       "Criptografia em andamento." if state == "encrypting" else "")]
    if state == "suspended":
        return [warn("bitlocker", f"BitLocker suspenso em {drive}", Severity.MEDIUM,
                     "O disco esta criptografado mas a chave fica acessivel sem protecao.",
                     "Resume-BitLocker -MountPoint " + drive + "   (como admin)")]
    if state in ("off", "decrypting"):
        return [failed("bitlocker", f"Disco do sistema ({drive}) sem criptografia", sev,
                       f"{risk}, todos os arquivos podem ser lidos plugando o disco em outro PC.", fix)]
    return [info("bitlocker", "Estado do BitLocker desconhecido",
                 "Nao foi possivel ler o status." + ("" if ctx.is_admin else " Rode como administrador."))]
