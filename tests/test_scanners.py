"""Tests for individual scanner modules."""

import json
import os
import pytest


def test_secrets_scanner_detects_aws_key(tmp_path):
    """Test that the secrets scanner detects AWS access keys."""
    from shieldmyrepo.scanners.secrets import SecretScanner

    test_file = tmp_path / "config.py"
    test_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')

    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))

    assert len(findings) >= 1
    assert any("AWS" in f.message for f in findings)


def test_secrets_scanner_detects_github_token(tmp_path):
    """Test that the secrets scanner detects GitHub tokens."""
    from shieldmyrepo.scanners.secrets import SecretScanner

    test_file = tmp_path / "script.sh"
    test_file.write_text('TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij')

    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))

    assert len(findings) >= 1
    assert any("GitHub" in f.message for f in findings)


def test_secrets_scanner_clean_repo(tmp_path):
    """Test that clean repos pass the secrets scanner."""
    from shieldmyrepo.scanners.secrets import SecretScanner

    test_file = tmp_path / "app.py"
    test_file.write_text('print("Hello, world!")\n')

    scanner = SecretScanner()
    findings = scanner.scan(str(tmp_path))

    assert len(findings) == 0


def test_dockerfile_scanner_detects_root(tmp_path):
    """Test that the Dockerfile scanner detects containers running as root."""
    from shieldmyrepo.scanners.dockerfile import DockerfileScanner

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.11\nRUN pip install flask\nCMD python app.py\n")

    scanner = DockerfileScanner()
    findings = scanner.scan(str(tmp_path))

    assert any("root" in f.message.lower() or "USER" in f.message for f in findings)


def test_dockerfile_scanner_detects_unpinned_image(tmp_path):
    """Test Dockerfile scanner detects unpinned base images."""
    from shieldmyrepo.scanners.dockerfile import DockerfileScanner

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM ubuntu:latest\nRUN apt-get update\n")

    scanner = DockerfileScanner()
    findings = scanner.scan(str(tmp_path))

    assert any("Unpinned" in f.message or "latest" in f.message for f in findings)


def test_gitignore_scanner_no_gitignore(tmp_path):
    """Test gitignore scanner flags missing .gitignore."""
    from shieldmyrepo.scanners.gitignore import GitignoreScanner

    scanner = GitignoreScanner()
    findings = scanner.scan(str(tmp_path))

    assert any(".gitignore" in f.message for f in findings)


def test_gitignore_scanner_detects_env_file(tmp_path):
    """Test gitignore scanner flags .env files not in .gitignore."""
    from shieldmyrepo.scanners.gitignore import GitignoreScanner

    env_file = tmp_path / ".env"
    env_file.write_text("SECRET_KEY=mysecret\n")

    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("*.pyc\n")

    scanner = GitignoreScanner()
    findings = scanner.scan(str(tmp_path))

    assert any(".env" in f.message for f in findings)


def test_dependency_scanner_unrequired(tmp_path):
    """Test dependency scanner handles projects without dependency files."""
    from shieldmyrepo.scanners.dependencies import DependencyScanner

    test_file = tmp_path / "main.py"
    test_file.write_text("print('hello')\n")

    scanner = DependencyScanner()
    findings = scanner.scan(str(tmp_path))

    # Should return an INFO finding about no dependency files
    assert any("No dependency" in f.message for f in findings)


def test_dependency_scanner_detects_unpinned(tmp_path):
    """Test dependency scanner detects unpinned Python dependencies."""
    from shieldmyrepo.scanners.dependencies import DependencyScanner

    req_file = tmp_path / "requirements.txt"
    req_file.write_text("flask\nrequests\n")

    scanner = DependencyScanner()
    findings = scanner.scan(str(tmp_path))

    assert any("Unpinned" in f.message for f in findings)
