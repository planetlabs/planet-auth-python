---
name: format
description: Auto-format code using Black via nox.
allowed-tools: Bash
---

Auto-format code using Black via nox.

Run: `nox -s black_format`

Black is configured in pyproject.toml with line-length=119.
