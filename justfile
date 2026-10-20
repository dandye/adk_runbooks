set dotenv-load := true

# Default environment file
env_file := ".env"

# Sphinx documentation configuration
sphinx_opts := "-c " + sphinx_sourcedir
sphinx_build := "sphinx-build"
sphinx_sourcedir := "rules-bank"
sphinx_builddir := "build"

# Default recipe: list available commands
default:
  @just --list

# ------------------------------------------------------------------------------
# Setup & Environment Management
# ------------------------------------------------------------------------------

# Setup local environment (.env files from templates, submodules, and sync uv dependencies)
setup:
  #!/usr/bin/env bash
  set -e
  git submodule update --init --recursive
  if [ ! -f "{{ env_file }}" ] && [ -f ".env.example" ]; then
    echo "Creating {{ env_file }} from .env.example..."
    cp .env.example "{{ env_file }}"
  fi
  if [ ! -f "multi-agent/manager/.env" ] && [ -f "multi-agent/manager/.env.example" ]; then
    echo "Creating multi-agent/manager/.env from template..."
    cp multi-agent/manager/.env.example multi-agent/manager/.env
  fi
  if [ ! -f "dac_agent/.env" ] && [ -f "dac_agent/.env.example" ]; then
    echo "Creating dac_agent/.env from template..."
    cp dac_agent/.env.example dac_agent/.env
  fi
  just sync

# Launch the interactive Bubble Tea TUI to configure .env files (initializes optional submodule on demand)
config-wizard *args="":
  #!/usr/bin/env bash
  set -euo pipefail
  if [ ! -f "external/secops-config-wizard/go.mod" ]; then
    echo "Initializing optional submodule external/secops-config-wizard..."
    git submodule update --init --checkout external/secops-config-wizard
  fi
  cd external/secops-config-wizard && go run . --repo-root ../.. {{ args }}

# Auto-discover SecOps configuration from /settings/profile (Chronicle API URL), clipboard, or gcloud
config-auto-discover *args="":
  #!/usr/bin/env bash
  set -euo pipefail
  if [ ! -f "external/secops-config-wizard/go.mod" ]; then
    echo "Initializing optional submodule external/secops-config-wizard..."
    git submodule update --init --checkout external/secops-config-wizard
  fi
  cd external/secops-config-wizard && go run . --repo-root ../.. --auto-discover {{ args }}

# Alias for config-wizard
configure *args="": (config-wizard args)

# Synchronize virtual environment and lock dependencies via uv
sync:
  uv sync --all-groups

# ------------------------------------------------------------------------------
# Quality & Testing (Google Python Style Guide)
# ------------------------------------------------------------------------------

# Run unit and evaluation tests with pytest
test *args="":
  uv run pytest {{ args }}

# Run tests with coverage report
test-cov:
  uv run pytest --cov=skills --cov=evals --cov=dac_agent --cov=multi-agent/manager --cov-report=term-missing --cov-report=html

# Check formatting with Pyink (Google Style: 2-space, 80-col)
format-check:
  uv run pyink --check --diff .

# Format code in-place with Pyink and apply Ruff fixes
format:
  uv run ruff check --fix .
  uv run pyink .

# Lint code against Google Python Style Guide (Pyink format check, then Ruff)
lint: format-check
  uv run ruff check .

# Static type analysis with Google Pytype
typecheck:
  uv run pytype

# Run the full CI gate locally (format check, lint, type analysis, tests)
check: lint typecheck test-cov

# ------------------------------------------------------------------------------
# Documentation (Sphinx & Rules Bank)
# ------------------------------------------------------------------------------

# Build Sphinx HTML documentation into build/html
html *args="":
  uv run {{ sphinx_build }} -M html "{{ sphinx_sourcedir }}" "{{ sphinx_builddir }}" {{ sphinx_opts }} {{ args }}

# Alias for building Sphinx HTML documentation
docs-build *args="": (html args)

# Run any Sphinx builder target (e.g., just sphinx dirhtml, just sphinx clean)
sphinx target="help" *args="":
  uv run {{ sphinx_build }} -M {{ target }} "{{ sphinx_sourcedir }}" "{{ sphinx_builddir }}" {{ sphinx_opts }} {{ args }}

# ------------------------------------------------------------------------------
# Agents & Evaluations
# ------------------------------------------------------------------------------

# Run the Multi-Agent Manager CLI
run-manager *args="":
  cd multi-agent && uv run adk run manager {{ args }}

# Start the ADK Web UI from the multi-agent directory
web *args="":
  cd multi-agent && uv run adk web {{ args }}

# Run the Detection-as-Code (DAC) Agent CLI
run-dac *args="":
  cd dac_agent && uv run adk run dac_agent {{ args }}

# Run declarative workflow evaluation benchmarks (core_workflows, all_36_workflows, expanded_cases_alerts)
eval dataset="core_workflows" *args="--report":
  uv run python -m evals.runner --dataset {{ dataset }} {{ args }}

# Clean build artifacts, bytecode, and test caches
clean:
  find . -path ./external -prune -o -type f -name "*.pyc" -delete
  find . -path ./external -prune -o -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
  rm -rf .pytest_cache .pytype .mypy_cache .ruff_cache .coverage htmlcov dist build *.egg-info
