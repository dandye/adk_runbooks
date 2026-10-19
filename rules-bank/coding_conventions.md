---
type: Guideline
title: "Coding Conventions"
description: "Style guides, naming standards, and coding conventions for Markdown runbooks, YARA-L rules, and Python automation tools."
generated:
  by: human:dandye
  at: 2025-05-17T18:46:00-04:00
related:
  - ./detection_strategy.md
  - ./data_normalization_map.md
---

# Coding Conventions

This document outlines the coding conventions for the Python code within `adk_runbooks` and `google-mcp-security`. The project strictly follows the [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html).

Code formatting, linting, import sorting, and static type checking are enforced automatically using `pyink`, `ruff`, and `pytype`. These tools are configured in the root `pyproject.toml` file and executed via `justfile` recipes (`just format`, `just lint`, `just typecheck`, and `just check`).

Key aspects enforced by the tools include:

*   **Line Length:** 80 characters (configured for both `pyink` and `ruff`).
*   **Indentation:** 2 spaces per block indentation level (`pyink-indentation = 2`), with 4 spaces for hanging continuation indents. Never use tabs or mix indentation within a file.
*   **Quotes:** Primarily double quotes (`"`), with `pyink-use-majority-quotes = true`.
*   **Imports:** Sorted alphabetically with single-line imports (`force-single-line = true`) via `ruff` (`I`).
*   **Static Type Checking:** Verified across packages via `pytype` (`just typecheck`).
*   **Docstrings:** Use triple double quotes (`"""Docstring"""`) following Google style guide conventions (`Args:`, `Returns:`, `Raises:`).

While the tools handle most formatting, developers should still adhere to other aspects of the Google style guide, such as naming conventions and general best practices.
