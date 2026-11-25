"""Helper para executar PowerShell e obter JSON."""
from __future__ import annotations

import json
import subprocess


class PSError(RuntimeError):
    pass


def run_ps(command: str, timeout: int = 60, depth: int = 3):
    """Executa um comando PowerShell e retorna o resultado convertido de JSON.

    Retorna None se o comando nao produzir saida. Sempre devolve lista quando o
    PowerShell retornar varios objetos.
    """
    script = (
        "$ProgressPreference='SilentlyContinue';"
        "$ErrorActionPreference='Stop';"
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
        f"$r = & {{ {command} }}; if ($null -ne $r) {{ $r | ConvertTo-Json -Depth {depth} -Compress }}"
    )
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", script],
            capture_output=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except FileNotFoundError as e:
        raise PSError("powershell.exe nao encontrado") from e
    except subprocess.TimeoutExpired as e:
        raise PSError(f"timeout apos {timeout}s") from e

    out = proc.stdout.decode("utf-8", errors="replace").strip()
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise PSError(_first_line(err) or f"exit code {proc.returncode}")
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError as e:
        raise PSError(f"saida invalida: {out[:200]}") from e


def as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _first_line(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return ""
