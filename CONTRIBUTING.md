# Contributing to ShieldMyRepo

First off, **thank you** for considering contributing to ShieldMyRepo! 🎉

Every contribution matters — whether it's fixing a typo, adding a new scanner module, or improving the documentation.

## 📋 Table of Contents

- [Getting Started](#-getting-started)
- [How to Contribute](#-how-to-contribute)
- [Adding a New Scanner Module](#-adding-a-new-scanner-module)
- [Code Style](#-code-style)
- [Pull Request Process](#-pull-request-process)

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git

### Setup

1. **Fork the repository** on GitHub

2. **Clone your fork**
   ```bash
   git clone https://github.com/YOUR_USERNAME/ShieldMyRepo.git
   cd ShieldMyRepo
   ```

3. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

4. **Install in development mode**
   ```bash
   pip install -e ".[dev]"
   ```

5. **Create a new branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

## 💡 How to Contribute

### 🟢 Easy (Good First Issues)
- Add new secret detection patterns (API keys, tokens)
- Improve error messages
- Add more entries to the gitignore scanner
- Write tests for existing scanners
- Fix typos or improve documentation

### 🟡 Medium
- Build a new scanner module (see below)
- Add support for new dependency file formats
- Improve the grading algorithm
- Add output format options (HTML, Markdown)

### 🔴 Hard
- Add GitHub API integration for remote repo scanning
- Build the web dashboard
- Implement git history scanning for leaked secrets
- Add AI-powered code analysis

## 🔌 Adding a New Scanner Module

This is one of the **easiest and most impactful** ways to contribute! Each scanner is a single Python file.

### Step 1: Create the scanner file

Create a new file in `shieldmyrepo/scanners/`:

```python
"""
Scanner: Your Scanner Name
Description: What this scanner checks for
"""

from shieldmyrepo.scanner_registry import ScannerBase, Finding, Severity


class YourScanner(ScannerBase):
    """Brief description of what this scanner does."""

    name = "Your Scanner Name"
    description = "What this scanner checks for"

    def scan(self, repo_path: str) -> list[Finding]:
        findings = []

        # Your scanning logic here
        # For each issue found, append a Finding:
        #
        # findings.append(Finding(
        #     severity=Severity.HIGH,
        #     file="path/to/file",
        #     line=42,
        #     message="Description of the issue",
        #     recommendation="How to fix it"
        # ))

        return findings
```

### Step 2: Register the scanner

The scanner is **automatically discovered** — just place it in the `shieldmyrepo/scanners/` directory and it will be picked up.

### Step 3: Add tests

Create a corresponding test file in `tests/`:

```python
import pytest
from shieldmyrepo.scanners.your_scanner import YourScanner


def test_your_scanner_detects_issue(tmp_path):
    # Create a test file with a known issue
    test_file = tmp_path / "bad_file.txt"
    test_file.write_text("some vulnerable content")

    scanner = YourScanner()
    findings = scanner.scan(str(tmp_path))

    assert len(findings) > 0
    assert findings[0].severity == Severity.HIGH
```

### Step 4: Submit a PR

- Describe what your scanner checks for
- Include test results
- Add an entry to the scanner table in `README.md`

## 🎨 Code Style

- Follow [PEP 8](https://pep8.org/) conventions
- Use type hints where possible
- Write docstrings for all public functions and classes
- Keep functions focused and small

## 📝 Pull Request Process

1. **Update documentation** if you're adding new features
2. **Add tests** for any new functionality
3. **Run existing tests** to make sure nothing is broken:
   ```bash
   pytest
   ```
4. **Fill out the PR template** with a clear description
5. **Request review** — a maintainer will review your PR

### Commit Messages

Use clear, descriptive commit messages:
- `feat: add AWS key detection to secrets scanner`
- `fix: handle missing package.json gracefully`
- `docs: update scanner table in README`
- `test: add tests for dockerfile scanner`

## 🙏 Thank You

Your contributions make ShieldMyRepo better for everyone. Whether it's your first open-source contribution or your hundredth, we appreciate your time and effort!

If you have questions, feel free to [open an issue](https://github.com/DhanushNehru/ShieldMyRepo/issues) and we'll be happy to help.
