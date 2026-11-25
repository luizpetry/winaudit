"""Leitura somente-leitura do registro do Windows."""
from __future__ import annotations

import winreg

HIVES = {
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKCU": winreg.HKEY_CURRENT_USER,
}

_MISSING = object()


def read_value(path: str, name: str, default=None, view64: bool = True):
    """Le um valor. `path` comeca com HKLM\\ ou HKCU\\."""
    hive, sub = _split(path)
    access = winreg.KEY_READ | (winreg.KEY_WOW64_64KEY if view64 else winreg.KEY_WOW64_32KEY)
    try:
        with winreg.OpenKey(hive, sub, 0, access) as k:
            value, _ = winreg.QueryValueEx(k, name)
            return value
    except OSError:
        return default


def key_exists(path: str) -> bool:
    hive, sub = _split(path)
    try:
        with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY):
            return True
    except OSError:
        return False


def list_values(path: str, view64: bool = True) -> list[tuple[str, object]]:
    hive, sub = _split(path)
    access = winreg.KEY_READ | (winreg.KEY_WOW64_64KEY if view64 else winreg.KEY_WOW64_32KEY)
    out = []
    try:
        with winreg.OpenKey(hive, sub, 0, access) as k:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                out.append((name, value))
                i += 1
    except OSError:
        pass
    return out


def list_subkeys(path: str, view64: bool = True) -> list[str]:
    hive, sub = _split(path)
    access = winreg.KEY_READ | (winreg.KEY_WOW64_64KEY if view64 else winreg.KEY_WOW64_32KEY)
    out = []
    try:
        with winreg.OpenKey(hive, sub, 0, access) as k:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return out


def _split(path: str):
    hive_name, _, sub = path.partition("\\")
    return HIVES[hive_name], sub
