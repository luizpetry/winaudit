"""Registro de checks.

Cada check e uma funcao `fn(ctx) -> list[Finding]` registrada com @check.
"""
from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass
from typing import Callable

from ..models import Finding


@dataclass
class Context:
    is_admin: bool
    enable_cve: bool = False
    # --cve-auto: tenta identificar no NVD tambem os programas fora do catalogo
    cve_auto: bool = False
    # mensagens de progresso para etapas demoradas (ex.: consultas ao NVD)
    progress: Callable[[str], None] | None = None
    # dados compartilhados entre checks (ex.: inventario de software para o CVE)
    shared: dict | None = None

    def __post_init__(self):
        if self.shared is None:
            self.shared = {}


@dataclass
class CheckDef:
    name: str
    category: str
    fn: Callable[[Context], list[Finding]]
    order: int = 100
    optional: bool = False  # so roda quando habilitado (ex.: --cve)


REGISTRY: list[CheckDef] = []


def check(name: str, category: str, order: int = 100, optional: bool = False):
    def deco(fn):
        REGISTRY.append(CheckDef(name, category, fn, order, optional))
        return fn
    return deco


def load_all() -> list[CheckDef]:
    for mod in pkgutil.iter_modules(__path__):
        importlib.import_module(f"{__name__}.{mod.name}")
    return sorted(REGISTRY, key=lambda c: c.order)
