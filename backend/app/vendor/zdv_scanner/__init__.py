from .engine import ScanEngine, ScanResult

__all__ = ["ScanEngine", "ScanResult"]
__version__ = "0.1.0"

from .fuzzer import Fuzzer  # noqa: E402
from .target import Target  # noqa: E402
