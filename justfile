set dotenv-load := true

# Default environment file
env_file := ".env"

# Sphinx documentation configuration (can be overridden from CLI, e.g., just O="-W" html)
SOURCEDIR := "rules-bank"
BUILDDIR := "build"
SPHINXOPTS := "-c " + SOURCEDIR
SPHINXBUILD := "sphinx-build"
O := ""

# Default recipe: list available commands
default:
  @just --list

# ------------------------------------------------------------------------------
# Setup & Environment Management
# ------------------------------------------------------------------------------

# Initialize submodules, create .env files from templates, and install dependencies
setup:
  #!/usr/bin/env bash
  set -euo pipefail
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
  if [ ! -f "external/mcp-security/.env" ] && [ -f "external/mcp-security/.env.example" ]; then
    echo "Creating external/mcp-security/.env from template..."
    cp external/mcp-security/.env.example external/mcp-security/.env
  fi
  just sync

# Initialize the optional secops-config-wizard submodule on demand
install-config-wizard:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ ! -f "external/secops-config-wizard/go.mod" ]; then
    echo "Initializing optional submodule external/secops-config-wizard..."
    git submodule update --init --checkout external/secops-config-wizard
  fi

# Launch the interactive Bubble Tea TUI to configure .env files
config-wizard *args="": install-config-wizard
  cd external/secops-config-wizard && go run . --repo-root ../.. {{ args }}

# Auto-discover SecOps configuration from /settings/profile (Chronicle API URL), clipboard, or gcloud
config-auto-discover *args="": install-config-wizard
  cd external/secops-config-wizard && go run . --repo-root ../.. --auto-discover {{ args }}

# Alias for config-wizard
configure *args="": (config-wizard args)

# Create .venv and synchronize dependencies from requirements.txt and requirements-docs.txt
sync:
  #!/usr/bin/env bash
  set -euo pipefail
  if command -v uv >/dev/null 2>&1; then
    [ -d .venv ] || uv venv .venv
    uv pip install --python .venv/bin/python -r multi-agent/requirements.txt -r requirements-docs.txt pytest
  else
    [ -d .venv ] || python3 -m venv .venv
    .venv/bin/pip install --upgrade pip
    .venv/bin/pip install -r multi-agent/requirements.txt -r requirements-docs.txt pytest
  fi

# ------------------------------------------------------------------------------
# Agents & Interactive Web UI
# ------------------------------------------------------------------------------

# Run the Multi-Agent Manager CLI interactively (adk run manager)
run-manager *args="":
  #!/usr/bin/env bash
  set -euo pipefail
  ADK_BIN="adk"
  if [ -x ".venv/bin/adk" ]; then ADK_BIN="../.venv/bin/adk"; elif [ -x "venv/bin/adk" ]; then ADK_BIN="../venv/bin/adk"; fi
  cd multi-agent && "$ADK_BIN" run manager {{ args }}

# Launch the interactive ADK Web UI from the multi-agent directory (adk web)
web *args="":
  #!/usr/bin/env bash
  set -euo pipefail
  ADK_BIN="adk"
  if [ -x ".venv/bin/adk" ]; then ADK_BIN="../.venv/bin/adk"; elif [ -x "venv/bin/adk" ]; then ADK_BIN="../venv/bin/adk"; fi
  cd multi-agent && "$ADK_BIN" web {{ args }}

# Run the Detection-as-Code (DAC) Agent CLI
run-dac *args="":
  #!/usr/bin/env bash
  set -euo pipefail
  ADK_BIN="adk"
  if [ -x ".venv/bin/adk" ]; then ADK_BIN="../.venv/bin/adk"; elif [ -x "venv/bin/adk" ]; then ADK_BIN="../venv/bin/adk"; fi
  cd dac_agent && "$ADK_BIN" run dac_agent {{ args }}

# ------------------------------------------------------------------------------
# Testing & Evaluations
# ------------------------------------------------------------------------------

# Run unit and evaluation test suites with pytest
test *args="tests/ evals/tests/":
  #!/usr/bin/env bash
  set -euo pipefail
  PYTEST_BIN="pytest"
  if [ -x ".venv/bin/pytest" ]; then PYTEST_BIN=".venv/bin/pytest"; elif [ -x "venv/bin/pytest" ]; then PYTEST_BIN="venv/bin/pytest"; fi
  "$PYTEST_BIN" {{ args }}

# Run declarative workflow evaluation benchmarks (core_workflows, all_36_workflows, expanded_cases_alerts)
eval dataset="core_workflows" *args="--report":
  #!/usr/bin/env bash
  set -euo pipefail
  PYTHON_BIN="python3"
  if [ -x ".venv/bin/python" ]; then PYTHON_BIN=".venv/bin/python"; elif [ -x "venv/bin/python" ]; then PYTHON_BIN="venv/bin/python"; fi
  "$PYTHON_BIN" -m evals.runner --dataset {{ dataset }} {{ args }}

# ------------------------------------------------------------------------------
# Documentation (Sphinx & Rules Bank)
# ------------------------------------------------------------------------------

# Show Sphinx build targets
help:
  #!/usr/bin/env bash
  set -euo pipefail
  SPHINX_BIN="{{ SPHINXBUILD }}"
  if [ -x ".venv/bin/sphinx-build" ]; then SPHINX_BIN=".venv/bin/sphinx-build"; elif [ -x "venv/bin/sphinx-build" ]; then SPHINX_BIN="venv/bin/sphinx-build"; fi
  "$SPHINX_BIN" -M help "{{ SOURCEDIR }}" "{{ BUILDDIR }}" {{ SPHINXOPTS }} {{ O }}

# Build Sphinx HTML documentation into build/html
html *opts="":
  #!/usr/bin/env bash
  set -euo pipefail
  SPHINX_BIN="{{ SPHINXBUILD }}"
  if [ -x ".venv/bin/sphinx-build" ]; then SPHINX_BIN=".venv/bin/sphinx-build"; elif [ -x "venv/bin/sphinx-build" ]; then SPHINX_BIN="venv/bin/sphinx-build"; fi
  "$SPHINX_BIN" -M html "{{ SOURCEDIR }}" "{{ BUILDDIR }}" {{ SPHINXOPTS }} {{ O }} {{ opts }}

# Alias for building Sphinx HTML documentation
docs-build *opts="": (html opts)

# Route any Sphinx builder target to sphinx-build -M (e.g., just sphinx dirhtml)
sphinx target="help" *opts="":
  #!/usr/bin/env bash
  set -euo pipefail
  SPHINX_BIN="{{ SPHINXBUILD }}"
  if [ -x ".venv/bin/sphinx-build" ]; then SPHINX_BIN=".venv/bin/sphinx-build"; elif [ -x "venv/bin/sphinx-build" ]; then SPHINX_BIN="venv/bin/sphinx-build"; fi
  "$SPHINX_BIN" -M {{ target }} "{{ SOURCEDIR }}" "{{ BUILDDIR }}" {{ SPHINXOPTS }} {{ O }} {{ opts }}

# Clean Sphinx build directory, bytecode, and test caches
clean:
  find . -path ./external -prune -o -type f -name "*.pyc" -delete
  find . -path ./external -prune -o -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
  rm -rf .pytest_cache .pytype .mypy_cache .ruff_cache .coverage htmlcov dist "{{ BUILDDIR }}" *.egg-info
