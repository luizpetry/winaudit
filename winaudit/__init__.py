import sys
from pathlib import Path

__version__ = "0.1.0"


def prog() -> str:
    """Como o usuario chamou o programa, para as dicas mostrarem o comando certo:
    'python -m winaudit' quando o atalho 'winaudit' nao esta no PATH."""
    return "python -m winaudit" if Path(sys.argv[0]).name == "__main__.py" else "winaudit"
