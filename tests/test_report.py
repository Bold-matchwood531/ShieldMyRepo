"""Tests for the report generator."""

from io import StringIO
from rich.console import Console

from shieldmyrepo.scanner_registry import Finding, ScanResult, Severity
from shieldmyrepo.report import render_report, _generate_markdown_report


def test_no_findings_shows_no_vulnerabilities_message(tmp_path):
    results = [
        ScanResult(scanner_name="Secret Detection", scanner_description="test", findings=[]),
    ]
    report = render_report(results, str(tmp_path))

    # markdown report should contain the message
    md = _generate_markdown_report(report)
    assert "No vulnerabilities detected" in md


def test_findings_present_does_not_show_no_vulnerabilities(tmp_path):
    results = [
        ScanResult(
            scanner_name="Secret Detection",
            scanner_description="test",
            findings=[Finding(severity=Severity.HIGH, message="leak")],
        ),
    ]
    report = render_report(results, str(tmp_path))

    md = _generate_markdown_report(report)
    assert "No vulnerabilities detected" not in md
    assert "leak" in md
