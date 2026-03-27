import os as _os

def _read_version() -> str:
    _version_file = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "VERSION")
    try:
        with open(_version_file) as _f:
            return _f.read().strip()
    except FileNotFoundError:
        return "unknown"

__version__ = _read_version()

from core.config import AresConfig
from core.logger import console
from core.utils import run_command, check_tool
