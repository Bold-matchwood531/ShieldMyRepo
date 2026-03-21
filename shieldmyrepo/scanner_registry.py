"""
Scanner registry and base classes.

This module provides the plugin architecture for ShieldMyRepo scanners.
Each scanner is a self-contained module that inherits from ScannerBase.
Scanners are auto-discovered from the scanners/ directory.
"""

import importlib
import inspect
import os
import pkgutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    """Severity levels for security findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Represents a single security finding from a scanner."""
    severity: Severity
    message: str
    file: Optional[str] = None
    line: Optional[int] = None
    recommendation: str = ""

    @property
    def severity_score(self) -> int:
        """Numeric score for severity (higher = worse)."""
        scores = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 8,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }
        return scores[self.severity]


@dataclass
class ScanResult:
    """Result from a single scanner run."""
    scanner_name: str
    scanner_description: str
    findings: List[Finding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """Scanner passed if no HIGH or CRITICAL findings."""
        return not any(
            f.severity in (Severity.CRITICAL, Severity.HIGH)
            for f in self.findings
        )

    @property
    def has_warnings(self) -> bool:
        """Scanner has warnings if MEDIUM or LOW findings exist."""
        return any(
            f.severity in (Severity.MEDIUM, Severity.LOW)
            for f in self.findings
        )

    @property
    def status(self) -> str:
        """Overall status: PASS, WARN, or FAIL."""
        if not self.findings:
            return "PASS"
        if self.passed and self.has_warnings:
            return "WARN"
        if not self.passed:
            return "FAIL"
        return "PASS"

    @property
    def total_score_deduction(self) -> int:
        """Total score deduction from findings."""
        return sum(f.severity_score for f in self.findings)


class ScannerBase(ABC):
    """Base class for all scanner modules.

    To create a new scanner:
    1. Create a new file in shieldmyrepo/scanners/
    2. Create a class that inherits from ScannerBase
    3. Set the 'name' and 'description' class attributes
    4. Implement the 'scan' method
    5. That's it! The scanner will be auto-discovered.
    """

    name: str = "Base Scanner"
    description: str = "Base scanner class"

    @abstractmethod
    def scan(self, repo_path: str) -> List[Finding]:
        """Scan the repository and return a list of findings.

        Args:
            repo_path: Absolute path to the repository root.

        Returns:
            List of Finding objects for any issues detected.
        """
        pass

    def run(self, repo_path: str) -> ScanResult:
        """Execute the scanner and return a ScanResult.

        This method wraps the scan() method with error handling.
        """
        try:
            findings = self.scan(repo_path)
            return ScanResult(
                scanner_name=self.name,
                scanner_description=self.description,
                findings=findings,
            )
        except Exception as e:
            return ScanResult(
                scanner_name=self.name,
                scanner_description=self.description,
                findings=[
                    Finding(
                        severity=Severity.INFO,
                        message=f"Scanner error: {str(e)}",
                        recommendation="Please report this as a bug.",
                    )
                ],
            )


class ScannerRegistry:
    """Auto-discovers and manages scanner modules."""

    def __init__(self):
        self._scanners: List[ScannerBase] = []

    def discover(self) -> None:
        """Auto-discover scanner modules from the scanners package."""
        scanners_dir = os.path.join(os.path.dirname(__file__), "scanners")
        package_name = "shieldmyrepo.scanners"

        for _, module_name, _ in pkgutil.iter_modules([scanners_dir]):
            if module_name.startswith("_"):
                continue

            try:
                module = importlib.import_module(f"{package_name}.{module_name}")
                for _, obj in inspect.getmembers(module, inspect.isclass):
                    if (
                        issubclass(obj, ScannerBase)
                        and obj is not ScannerBase
                        and not inspect.isabstract(obj)
                    ):
                        self._scanners.append(obj())
            except Exception:
                continue

    def get_scanners(self, names: Optional[List[str]] = None) -> List[ScannerBase]:
        """Get scanners, optionally filtered by name.

        Args:
            names: Optional list of scanner names to filter by.

        Returns:
            List of scanner instances.
        """
        if not self._scanners:
            self.discover()

        if names:
            name_set = {n.lower() for n in names}
            return [s for s in self._scanners if s.name.lower() in name_set]

        return self._scanners

    def list_scanners(self) -> List[dict]:
        """List all available scanners with their metadata."""
        if not self._scanners:
            self.discover()

        return [
            {"name": s.name, "description": s.description}
            for s in self._scanners
        ]
