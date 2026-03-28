---
name: check-all
description: Run the full default nox session suite (lint, test, security scan). Equivalent to CI pipeline checks.
allowed-tools: Bash
---

Run the full default nox session suite: black lint check, pytest, semgrep security scan, mypy, pyflakes, and pylint.

This is equivalent to the CI pipeline checks.

Run: `nox`
