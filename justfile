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
[private]
default:
  @just --list --unsorted --list-heading $'ADK Runbooks — Available Commands\n\n' --list-prefix "    "

# ------------------------------------------------------------------------------
# Setup & Configuration
# ------------------------------------------------------------------------------

# Setup .env files from templates, initialize submodules, and sync dependencies
[group('Setup & Configuration')]
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

# Auto-discover SecOps settings from /settings/profile, clipboard, or gcloud (pure Python)
[group('Setup & Configuration')]
config-auto-discover *args="":
  #!/usr/bin/env python3
  import json, os, pathlib, re, shlex, subprocess, sys, urllib.request, uuid

  RESOURCE_RE = re.compile(r"projects/([^/\s\"']+)/locations/([^/\s\"']+)/instances/([0-9a-fA-F-]{36})", re.I)
  UUID4_RE = re.compile(r"\b([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\b", re.I)
  PROJ_NUM_RE = re.compile(r"^\d{6,20}$")
  PLACEHOLDERS = {
      "", "your-gcp-project-id", "your_gcp_project_id", "your-project-id",
      "your-chronicle-customer-id", "your_chronicle_customer_id",
      "76543210-dcba-4321-abcd-ba9876543210", "https://your-soar-instance.siemplify-soar.com",
      "https://your-code-here.siemplify-soar.com", "https://your-soar-instance.example.com",
      "your-soar-app-key", "your_soar_app_key", "01234567-abcd-4321-abcd-0123456789ab",
      "your-virustotal-api-key", "your_virustotal_api_key", "your-gemini-api-key",
      "your_google_api_key_here", "[redacted]",
  }

  def parse_env_file(path: pathlib.Path) -> dict[str, str]:
    res: dict[str, str] = {}
    if not path.is_file():
      return res
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
      line = raw.strip()
      if not line or line.startswith("#") or "=" not in line:
        continue
      k, v = line.split("=", 1)
      k = re.sub(r"^export\s+", "", k.strip())
      v = v.split(" #", 1)[0].strip().strip("\"'")
      if v.lower() not in PLACEHOLDERS:
        res[k] = v
    return res

  def run_quiet(cmd: list[str], timeout: float = 4.0) -> str:
    env = {**os.environ, "CLOUDSDK_CORE_DISABLE_PROMPTS": "1"}
    try:
      p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, check=False)
      return p.stdout.strip() if p.returncode == 0 else ""
    except Exception:
      return ""

  def parse_profile_text(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    m = RESOURCE_RE.search(text)
    if m:
      proj_or_num, reg, cid = m.group(1), m.group(2).lower(), m.group(3).lower()
      out["project_number" if PROJ_NUM_RE.match(proj_or_num) else "project_id"] = proj_or_num
      out["region"] = reg
      out["customer_id"] = cid
      out["source"] = "Chronicle API URL"
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for i, ln in enumerate(lines):
      low = ln.lower()
      val = ln.split(":", 1)[1].strip() if ":" in ln and not low.startswith("http") else (lines[i + 1] if i + 1 < len(lines) else "")
      if low == "customer id" or low.startswith("customer id:"):
        if UUID4_RE.fullmatch(val):
          out["customer_id"] = val.lower()
          out["source"] = "SecOps /settings/profile (Organization Details)"
      elif low == "gcp project id" or low.startswith("gcp project id:"):
        if val and not PROJ_NUM_RE.match(val):
          out["project_id"] = val
          out["source"] = "SecOps /settings/profile (Organization Details)"
      elif low == "gcp project number" or low.startswith("gcp project number:"):
        if PROJ_NUM_RE.match(val):
          out["project_number"] = val
      elif low == "region" or low.startswith("region:"):
        if val:
          out["region"] = val.lower()
    if "customer_id" not in out:
      u = UUID4_RE.search(text)
      if u:
        out["customer_id"] = u.group(1).lower()
        out.setdefault("source", "UUIDv4 input")
    return out

  raw_args = shlex.split("""{{ args }}""")
  dry_run = "--dry-run" in raw_args
  positional = [a for a in raw_args if not a.startswith("-")]
  input_text = " ".join(positional).strip()

  existing: dict[str, str] = {}
  for rel in ("external/mcp-security/.env", "dac_agent/.env", "multi-agent/manager/.env", ".env"):
    existing.update(parse_env_file(pathlib.Path(rel)))

  discovered: dict[str, str] = {}
  if input_text:
    discovered = parse_profile_text(input_text)
    if not discovered.get("customer_id"):
      sys.exit(f"Error: could not parse a valid Chronicle API URL or UUIDv4 from: {input_text}")

  if not discovered.get("customer_id"):
    for clip_cmd in (["pbpaste"], ["wl-paste", "--no-newline"], ["xclip", "-o", "-selection", "clipboard"], ["xsel", "-ob"]):
      clip = run_quiet(clip_cmd, timeout=1.0)
      if clip and RESOURCE_RE.search(clip):
        discovered = parse_profile_text(clip)
        discovered["source"] = "System Clipboard (Chronicle API URL)"
        break

  if not discovered.get("customer_id"):
    if not sys.stdin.isatty():
      piped = sys.stdin.read().strip()
      if piped:
        discovered = parse_profile_text(piped)
    else:
      print("Google SecOps Auto-Discovery (/settings/profile)")
      print("1. Open https://<tenant>.backstory.chronicle.security/settings/profile")
      print("2. Under 'Organization Details', click Copy next to 'Chronicle API URL' (or copy the card text).")
      pasted = input("Paste Chronicle API URL (or press Enter to use existing/default values): ").strip()
      if pasted:
        discovered = parse_profile_text(pasted)
        if not discovered.get("customer_id"):
          sys.exit("Error: could not find a valid Chronicle Customer ID (UUIDv4) in pasted text.")

  cid = discovered.get("customer_id") or existing.get("CHRONICLE_CUSTOMER_ID") or "a13f6726-efed-452e-9008-8fe0d3cb0f75"
  reg = discovered.get("region") or existing.get("CHRONICLE_REGION") or "us"
  pnum = discovered.get("project_number", "")
  pid = discovered.get("project_id", "")

  if not pid and (pnum or cid):
    tenants_dir = pathlib.Path.home() / ".config" / "secops-tenants"
    if tenants_dir.is_dir():
      for tf in sorted(tenants_dir.glob("*.env")):
        kv = parse_env_file(tf)
        t_pid = kv.get("CHRONICLE_PROJECT_ID") or kv.get("GOOGLE_CLOUD_PROJECT") or kv.get("PROJECT_ID") or ""
        t_num = kv.get("GCP_PROJECT_NUMBER") or kv.get("PROJECT_NUMBER") or ""
        t_cid = kv.get("CHRONICLE_CUSTOMER_ID") or kv.get("CUSTOMER_ID") or kv.get("PROJECT_INSTANCE") or ""
        if t_pid and ((pnum and t_num == pnum) or (cid and t_cid.lower() == cid.lower())):
          pid = t_pid
          break
    if not pid and pnum:
      pid = run_quiet(["gcloud", "projects", "describe", pnum, "--format=value(projectId)"], timeout=5.0) or pnum

  if not pid:
    pid = existing.get("CHRONICLE_PROJECT_ID") or existing.get("GOOGLE_CLOUD_PROJECT") or "secops-demo-env"

  soar_url = existing.get("SOAR_URL", "")
  soar_key = existing.get("SOAR_APP_KEY", "")
  vt_key = existing.get("VT_APIKEY", "")
  gemini_key = existing.get("GOOGLE_API_KEY", "")
  loc = existing.get("GOOGLE_CLOUD_LOCATION", "global")
  mode = existing.get("ADK_DISCLOSURE_MODE", "dual_progressive")
  source = discovered.get("source") or "existing/default .env configuration"

  soar_lines = f"SOAR_URL={soar_url}\nSOAR_APP_KEY={soar_key}" if soar_url else "# SOAR_URL=\n# SOAR_APP_KEY="
  env_body = (
      f"# Generated by just config-auto-discover\n"
      f"GOOGLE_GENAI_USE_VERTEXAI=TRUE\n"
      f"GOOGLE_CLOUD_PROJECT={pid}\n"
      f"GOOGLE_CLOUD_LOCATION={loc}\n"
      f"GOOGLE_API_KEY={gemini_key}\n\n"
      f"CHRONICLE_PROJECT_ID={pid}\n"
      f"CHRONICLE_CUSTOMER_ID={cid}\n"
      f"CHRONICLE_REGION={reg}\n\n"
      f"{soar_lines}\n"
      f"VT_APIKEY={vt_key}\n"
      f"ADK_DISCLOSURE_MODE={mode}\n"
  )

  targets = [pathlib.Path(".env"), pathlib.Path("multi-agent/manager/.env"), pathlib.Path("dac_agent/.env")]
  if pathlib.Path("external/mcp-security").is_dir():
    targets.append(pathlib.Path("external/mcp-security/.env"))

  written = []
  if not dry_run:
    for t in targets:
      t.parent.mkdir(parents=True, exist_ok=True)
      t.write_text(env_body, encoding="utf-8")
      written.append(str(t))

  title = "Google SecOps Auto-Discovery (Dry Run - No Files Written)" if dry_run else "Google SecOps Auto-Discovery Complete"
  print(f"╭{'─' * 86}╮")
  print(f"│  {title:<84}│")
  print(f"│  {'':<84}│")
  print(f"│  {'Discovery Source:':<24}{source:<60}│")
  print(f"│  {'CHRONICLE_PROJECT_ID:':<24}{pid:<60}│")
  if pnum:
    print(f"│  {'GCP Project Number:':<24}{pnum:<60}│")
  print(f"│  {'CHRONICLE_CUSTOMER_ID:':<24}{cid:<60}│")
  print(f"│  {'CHRONICLE_REGION:':<24}{reg:<60}│")
  soar_desc = f"Standalone SOAR ({soar_url})" if soar_url else "Google Cloud (gcom migrated)"
  print(f"│  {'SOAR API Mode:':<24}{soar_desc:<60}│")
  if written:
    print(f"│  {'Written Files:':<24}{', '.join(written):<60}│")
  print(f"╰{'─' * 86}╯")

# Launch the interactive Bubble Tea TUI to configure .env files (installs submodule on demand)
[group('Setup & Configuration')]
config-wizard *args="": config-wizard-install
  cd external/secops-config-wizard && go run . --repo-root ../.. {{ args }}

alias configure := config-wizard

# Initialize the optional secops-config-wizard Go TUI submodule on demand
[group('Setup & Configuration')]
config-wizard-install:
  #!/usr/bin/env bash
  set -euo pipefail
  if [ ! -f "external/secops-config-wizard/go.mod" ]; then
    echo "Initializing optional submodule external/secops-config-wizard..."
    git submodule update --init --checkout external/secops-config-wizard
  fi

# Create .venv and synchronize dependencies from requirements.txt and requirements-docs.txt
[group('Setup & Configuration')]
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
# Agents & Evaluations
# ------------------------------------------------------------------------------

# Launch the interactive ADK Web UI (adk web; runs setup first)
[group('Agents & Evaluations')]
adk-web *args="": setup
  #!/usr/bin/env bash
  set -euo pipefail
  ADK_BIN="adk"
  if [ -x ".venv/bin/adk" ]; then ADK_BIN="../.venv/bin/adk"; elif [ -x "venv/bin/adk" ]; then ADK_BIN="../venv/bin/adk"; fi
  cd multi-agent && "$ADK_BIN" web {{ args }}

alias web := adk-web

# Run the Multi-Agent Manager CLI interactively (adk run manager)
[group('Agents & Evaluations')]
run-manager *args="":
  #!/usr/bin/env bash
  set -euo pipefail
  ADK_BIN="adk"
  if [ -x ".venv/bin/adk" ]; then ADK_BIN="../.venv/bin/adk"; elif [ -x "venv/bin/adk" ]; then ADK_BIN="../venv/bin/adk"; fi
  cd multi-agent && "$ADK_BIN" run manager {{ args }}

# Run the Detection-as-Code (DAC) Agent CLI
[group('Agents & Evaluations')]
run-dac *args="":
  #!/usr/bin/env bash
  set -euo pipefail
  ADK_BIN="adk"
  if [ -x ".venv/bin/adk" ]; then ADK_BIN="../.venv/bin/adk"; elif [ -x "venv/bin/adk" ]; then ADK_BIN="../venv/bin/adk"; fi
  cd dac_agent && "$ADK_BIN" run dac_agent {{ args }}

# Run workflow evaluation benchmarks (e.g., core_workflows, all_36_workflows)
[group('Agents & Evaluations')]
eval dataset="core_workflows" *args="--report":
  #!/usr/bin/env bash
  set -euo pipefail
  PYTHON_BIN="python3"
  if [ -x ".venv/bin/python" ]; then PYTHON_BIN=".venv/bin/python"; elif [ -x "venv/bin/python" ]; then PYTHON_BIN="venv/bin/python"; fi
  "$PYTHON_BIN" -m evals.runner --dataset {{ dataset }} {{ args }}

# ------------------------------------------------------------------------------
# Quality & Testing
# ------------------------------------------------------------------------------

# Run unit and evaluation test suites with pytest
[group('Quality & Testing')]
test *args="tests/ evals/tests/":
  #!/usr/bin/env bash
  set -euo pipefail
  PYTEST_BIN="pytest"
  if [ -x ".venv/bin/pytest" ]; then PYTEST_BIN=".venv/bin/pytest"; elif [ -x "venv/bin/pytest" ]; then PYTEST_BIN="venv/bin/pytest"; fi
  "$PYTEST_BIN" {{ args }}

# ------------------------------------------------------------------------------
# Documentation & Maintenance
# ------------------------------------------------------------------------------

# Build Sphinx HTML documentation into build/html
[group('Documentation & Maintenance')]
html *opts="":
  #!/usr/bin/env bash
  set -euo pipefail
  SPHINX_BIN="{{ SPHINXBUILD }}"
  if [ -x ".venv/bin/sphinx-build" ]; then SPHINX_BIN=".venv/bin/sphinx-build"; elif [ -x "venv/bin/sphinx-build" ]; then SPHINX_BIN="venv/bin/sphinx-build"; fi
  "$SPHINX_BIN" -M html "{{ SOURCEDIR }}" "{{ BUILDDIR }}" {{ SPHINXOPTS }} {{ O }} {{ opts }}

alias docs-build := html

# Route any Sphinx builder target to sphinx-build -M (e.g., just sphinx dirhtml)
[group('Documentation & Maintenance')]
sphinx target="help" *opts="":
  #!/usr/bin/env bash
  set -euo pipefail
  SPHINX_BIN="{{ SPHINXBUILD }}"
  if [ -x ".venv/bin/sphinx-build" ]; then SPHINX_BIN=".venv/bin/sphinx-build"; elif [ -x "venv/bin/sphinx-build" ]; then SPHINX_BIN="venv/bin/sphinx-build"; fi
  "$SPHINX_BIN" -M {{ target }} "{{ SOURCEDIR }}" "{{ BUILDDIR }}" {{ SPHINXOPTS }} {{ O }} {{ opts }}

# Show Sphinx build targets
[group('Documentation & Maintenance')]
help:
  #!/usr/bin/env bash
  set -euo pipefail
  SPHINX_BIN="{{ SPHINXBUILD }}"
  if [ -x ".venv/bin/sphinx-build" ]; then SPHINX_BIN=".venv/bin/sphinx-build"; elif [ -x "venv/bin/sphinx-build" ]; then SPHINX_BIN="venv/bin/sphinx-build"; fi
  "$SPHINX_BIN" -M help "{{ SOURCEDIR }}" "{{ BUILDDIR }}" {{ SPHINXOPTS }} {{ O }}

# Clean Sphinx build directory, bytecode, and test caches
[group('Documentation & Maintenance')]
clean:
  find . -path ./external -prune -o -type f -name "*.pyc" -delete
  find . -path ./external -prune -o -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
  rm -rf .pytest_cache .pytype .mypy_cache .ruff_cache .coverage htmlcov dist "{{ BUILDDIR }}" *.egg-info
