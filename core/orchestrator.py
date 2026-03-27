"""
ARES - Orchestrator
Coordinates module execution in the correct order, passing context between phases.
"""
import time
import json
import os
from core.config import AresConfig
from core import logger
from modules import MODULE_REGISTRY


# Execution order: modules run in this sequence
EXECUTION_ORDER = ["nmap", "fuzzing", "bruteforce", "nuclei"]


class Orchestrator:
    """Main ARES engine. Runs modules in order and aggregates results."""

    def __init__(self, config: AresConfig):
        self.config = config
        self.results = {}
        self.start_time = 0

    def run(self):
        """Execute full scan pipeline."""
        self.start_time = time.time()

        # Setup workspace first so output_dir is resolved before printing
        self.config.setup_workspace()
        self.config.save()

        logger.print_banner()
        logger.info(f"Target   : {self.config.target_ip}")
        if self.config.hostname:
            logger.info(f"Hostname : {self.config.hostname}")
        logger.info(f"Output   : {self.config.output_dir}")
        logger.info(f"Intensity: {self.config.intensity}")
        logger.info(f"Threads  : {self.config.threads}")
        logger.info(f"Modules  : {', '.join(self.config.modules_enabled)}")
        logger.info(f"WL dirs  : {self.config.wordlist_web}")
        logger.info(f"WL files : {self.config.wordlist_web_files}")
        logger.info(f"WL users : {self.config.wordlist_users}")
        logger.info(f"WL pass  : {self.config.wordlist_passwords}")
        if self.config.proxy:
            logger.info(f"Proxy    : {self.config.proxy}")
        logger.console.print()

        # Check /etc/hosts
        if self.config.hostname:
            from core.utils import add_to_hosts
            add_to_hosts(self.config.target_ip, self.config.hostname)

        # Execute modules in order
        context = {}
        for module_name in EXECUTION_ORDER:
            if module_name not in self.config.modules_enabled:
                logger.info(f"Skipping {module_name} (disabled)")
                continue

            if module_name not in MODULE_REGISTRY:
                logger.warning(f"Unknown module: {module_name}")
                continue

            module_class = MODULE_REGISTRY[module_name]
            module = module_class(self.config)
            result = module.execute(context=context)

            # Store result and make available to next modules
            self.results[module_name] = result
            context[module_name] = result

        # Compute total time
        total_time = time.time() - self.start_time

        # Print summary
        logger.print_summary(self.results, total_time)

        # Generate reports
        self._generate_reports(total_time)

        # Save raw results as JSON
        results_file = os.path.join(self.config.output_dir, "ares_results.json")
        with open(results_file, "w") as f:
            json.dump(self._sanitize_results(), f, indent=2, default=str)
        logger.success(f"Results saved to {results_file}")

        return self.results

    def _generate_reports(self, total_time: float):
        """Generate output reports in requested formats."""
        if "markdown" in self.config.report_formats:
            try:
                from reporters.markdown import MarkdownReporter
                md = MarkdownReporter(self.config, self.results, total_time)
                path = md.generate()
                logger.success(f"Markdown report: {path}")
            except Exception as e:
                logger.error(f"Markdown report failed: {e}")

        if "html" in self.config.report_formats:
            try:
                from reporters.html_report import HTMLReporter
                html = HTMLReporter(self.config, self.results, total_time)
                path = html.generate()
                logger.success(f"HTML report: {path}")
            except Exception as e:
                logger.error(f"HTML report failed: {e}")

    def _sanitize_results(self) -> dict:
        """Clean results for JSON serialization."""
        sanitized = {}
        for key, value in self.results.items():
            if isinstance(value, dict):
                sanitized[key] = {k: v for k, v in value.items() if not k.startswith("_")}
            else:
                sanitized[key] = value
        return sanitized
