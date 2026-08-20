import sys
from pathlib import Path

# Add workspace root and multi-agent directory to sys.path
REPO_ROOT = Path(__file__).resolve().parents[2]
MULTI_AGENT_DIR = REPO_ROOT / "multi-agent"

for p in [str(REPO_ROOT), str(MULTI_AGENT_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)
