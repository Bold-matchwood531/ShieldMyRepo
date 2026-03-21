"""Tests for the scanner registry and base classes."""

import pytest
from shieldmyrepo.scanner_registry import (
    Finding, ScannerBase, ScannerRegistry, ScanResult, Severity
)


class MockScanner(ScannerBase):
    name = "Mock Scanner"
    description = "A mock scanner for testing"

    def scan(self, repo_path):
        return [
            Finding(
                severity=Severity.HIGH,
                message="Test finding",
                file="test.py",
                line=1,
                recommendation="Fix this",
            )
        ]


class CleanScanner(ScannerBase):
    name = "Clean Scanner"
    description = "A scanner that finds nothing"

    def scan(self, repo_path):
        return []


def test_finding_severity_score():
    finding = Finding(severity=Severity.CRITICAL, message="test")
    assert finding.severity_score == 10

    finding = Finding(severity=Severity.LOW, message="test")
    assert finding.severity_score == 2


def test_scan_result_status_pass():
    result = ScanResult(scanner_name="test", scanner_description="test", findings=[])
    assert result.status == "PASS"
    assert result.passed is True


def test_scan_result_status_fail():
    result = ScanResult(
        scanner_name="test",
        scanner_description="test",
        findings=[Finding(severity=Severity.HIGH, message="bad")]
    )
    assert result.status == "FAIL"
    assert result.passed is False


def test_scan_result_status_warn():
    result = ScanResult(
        scanner_name="test",
        scanner_description="test",
        findings=[Finding(severity=Severity.MEDIUM, message="meh")]
    )
    assert result.status == "WARN"


def test_scanner_run():
    scanner = MockScanner()
    result = scanner.run("/tmp")
    assert result.scanner_name == "Mock Scanner"
    assert len(result.findings) == 1
    assert result.status == "FAIL"


def test_clean_scanner():
    scanner = CleanScanner()
    result = scanner.run("/tmp")
    assert result.status == "PASS"
    assert len(result.findings) == 0


def test_registry_discover():
    registry = ScannerRegistry()
    registry.discover()
    scanners = registry.get_scanners()
    assert len(scanners) > 0
    names = [s.name for s in scanners]
    assert "Secret Detection" in names
