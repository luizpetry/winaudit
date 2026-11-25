import psutil

from ..models import Severity, info, passed, warn
from . import check

# portas que quase nunca deveriam estar expostas na rede numa estacao de trabalho
RISKY = {
    21: ("FTP", Severity.HIGH, "transmite senhas em texto puro"),
    23: ("Telnet", Severity.HIGH, "acesso remoto sem criptografia"),
    69: ("TFTP", Severity.MEDIUM, "transferencia de arquivos sem autenticacao"),
    1433: ("SQL Server", Severity.MEDIUM, "banco de dados acessivel pela rede"),
    1521: ("Oracle DB", Severity.MEDIUM, "banco de dados acessivel pela rede"),
    2375: ("Docker API", Severity.CRITICAL, "API do Docker sem TLS: controle total da maquina"),
    3306: ("MySQL", Severity.MEDIUM, "banco de dados acessivel pela rede"),
    5432: ("PostgreSQL", Severity.MEDIUM, "banco de dados acessivel pela rede"),
    5800: ("VNC (web)", Severity.HIGH, "controle remoto da tela"),
    5900: ("VNC", Severity.HIGH, "controle remoto da tela"),
    5985: ("WinRM HTTP", Severity.MEDIUM, "execucao remota de comandos"),
    6379: ("Redis", Severity.HIGH, "geralmente sem senha"),
    9200: ("Elasticsearch", Severity.HIGH, "geralmente sem autenticacao"),
    11211: ("Memcached", Severity.MEDIUM, "sem autenticacao"),
    27017: ("MongoDB", Severity.HIGH, "geralmente sem autenticacao"),
}
# padroes do Windows: so listados como informacao
WINDOWS_DEFAULT = {135, 139, 445, 5040, 5357, 7680}


def _proc_name(pid) -> str:
    if not pid:
        return "?"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return f"pid {pid}"


def listening_exposed():
    """Retorna {porta: (ip, nome_processo)} para sockets TCP ouvindo fora do loopback."""
    out = {}
    for c in psutil.net_connections(kind="tcp"):
        if c.status != psutil.CONN_LISTEN or not c.laddr:
            continue
        ip = c.laddr.ip
        if ip.startswith("127.") or ip == "::1":
            continue
        port = c.laddr.port
        if port not in out:
            out[port] = (ip, _proc_name(c.pid))
    return out


@check("ports", "Rede", order=60)
def ports(ctx):
    exposed = listening_exposed()
    findings = []
    for port in sorted(exposed):
        if port in RISKY:
            svc, sev, why = RISKY[port]
            ip, proc = exposed[port]
            findings.append(warn(f"ports.{port}", f"Porta {port} ({svc}) aberta para a rede", sev,
                                 f"{proc} esta ouvindo em {ip}:{port} ({why}). "
                                 "O firewall pode estar bloqueando, mas o servico esta exposto se a regra permitir.",
                                 f"Se nao usa, pare o servico. Se usa, faca-o ouvir so em 127.0.0.1 "
                                 f"ou bloqueie: New-NetFirewallRule -DisplayName 'Bloquear {port}' -Direction Inbound "
                                 f"-LocalPort {port} -Protocol TCP -Action Block"))
    if not findings:
        findings.append(passed("ports.risky", "Nenhuma porta de alto risco exposta"))

    others = [f"{p} ({exposed[p][1]})" for p in sorted(exposed)
              if p not in RISKY and p not in WINDOWS_DEFAULT and p < 49152]
    if others:
        findings.append(info("ports.other", f"{len(others)} outra(s) porta(s) ouvindo na rede",
                             "Confira se reconhece cada programa.", others))
    return findings
