"""
ARES - Base Module
All scan modules inherit from this class.
"""
import time
import os
from abc import ABC, abstractmethod
from core.config import AresConfig
from core import logger


class BaseModule(ABC):
    """Abstract base class for ARES scan modules."""

    name: str = "base"
    description: str = ""
    required_tools: list = []
    phase: int = 0  # 0=recon, 1=enumeration, 2=vuln, 3=exploit

    def __init__(self, config: AresConfig):
        self.config = config
        self.results = {}
        self.start_time = 0
        self.end_time = 0
        self.output_path = os.path.join(config.output_dir, self.name)

    def preflight(self) -> bool:
        """Check that required tools are available."""
        from core.utils import check_tool
        all_ok = True
        for tool in self.required_tools:
            if not check_tool(tool):
                logger.error(f"[{self.name}] Required tool missing: {tool}")
                all_ok = False
        return all_ok

    def execute(self, context: dict = None) -> dict:
        """Run the module with timing and error handling."""
        context = context or {}
        if not self.preflight():
            logger.error(f"[{self.name}] Skipping — missing dependencies")
            return {"error": "missing_tools", "skipped": True}

        logger.phase_start(
            f"{self.name.upper()} Module",
            self.description
        )
        self.start_time = time.time()

        try:
            self.results = self.run(context)
        except KeyboardInterrupt:
            logger.warning(f"[{self.name}] Interrupted by user")
            self.results = {"error": "interrupted"}
        except Exception as e:
            logger.error(f"[{self.name}] Unhandled error: {e}")
            self.results = {"error": str(e)}

        self.end_time = time.time()
        duration = self.end_time - self.start_time
        logger.phase_end(self.name.upper(), duration)
        self.results["_duration"] = round(duration, 2)
        return self.results

    @abstractmethod
    def run(self, context: dict) -> dict:
        """
        Core scan logic. Must be implemented by each module.
        
        Args:
            context: Dict with results from previous modules.
                     e.g., context["nmap"]["ports"] for port data.
        Returns:
            Dict with structured results.
        """
        pass

    def save_raw(self, filename: str, content: str):
        """Save raw output to the module's output directory."""
        filepath = os.path.join(self.output_path, filename)
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as f:
            f.write(content)
        return filepath
