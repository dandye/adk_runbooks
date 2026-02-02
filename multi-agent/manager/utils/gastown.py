import os
import subprocess
import yaml
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class Bead(BaseModel):
    """Represents a discrete unit of work (task) in the Gas Town model."""
    id: str
    description: str
    assigned_to: str
    status: str = Field(default="TODO", description="TODO, IN_PROGRESS, DONE, BLOCKED")
    notes: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    updated_at: str = Field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    context: Dict[str, Any] = Field(default_factory=dict)
    artifacts: List[str] = Field(default_factory=list)

    def to_yaml(self) -> str:
        return yaml.dump(self.model_dump(), sort_keys=False)

    @classmethod
    def from_yaml(cls, content: str) -> "Bead":
        data = yaml.safe_load(content)
        return cls(**data)

class GasTownMayor:
    """
    Manages the 'Town' (workspace) and implements the 'Propulsion Principle'
    (Git-backed state) for investigations.
    """
    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir:
            self.base_dir = base_dir
        else:
            # Default to multi-agent/active_investigations
            # Assumes this file is in multi-agent/manager/utils/gastown.py
            self.base_dir = Path(__file__).resolve().parent.parent.parent / "active_investigations"

        if not self.base_dir.exists():
            self.base_dir.mkdir(parents=True, exist_ok=True)

    def _run_git(self, cwd: Path, args: List[str]) -> str:
        try:
            result = subprocess.run(
                ["git"] + args,
                cwd=cwd,
                capture_output=True,
                text=True,
                check=True,
                env={**os.environ, "GIT_AUTHOR_NAME": "GasTown Mayor", "GIT_AUTHOR_EMAIL": "mayor@gastown.local", "GIT_COMMITTER_NAME": "GasTown Mayor", "GIT_COMMITTER_EMAIL": "mayor@gastown.local"}
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            # If git init is called on a non-empty dir it might fail or warn, but generally we want to know.
            # However, for 'git commit' with nothing to commit, it returns 1. We handle that.
            if "nothing to commit" in e.stdout or "nothing to commit" in e.stderr:
                return "Nothing to commit"
            raise Exception(f"Git command failed: {args} in {cwd}. Error: {e.stderr}") from e

    def create_investigation(self, case_id: str) -> str:
        """Initializes a new investigation workspace (Git repo)."""
        case_dir = self.base_dir / case_id
        if case_dir.exists():
            return f"Investigation {case_id} already exists at {case_dir}"

        case_dir.mkdir(parents=True)
        self._run_git(case_dir, ["init"])

        # Create a README
        readme_path = case_dir / "README.md"
        readme_path.write_text(f"# Investigation: {case_id}\n\nStarted at: {datetime.now()}\n")

        self._run_git(case_dir, ["add", "."])
        self._run_git(case_dir, ["commit", "-m", "Initial commit: Investigation started"])

        return f"Created investigation workspace at {case_dir}"

    def create_bead(self, case_id: str, description: str, assigned_to: str, context: Dict[str, Any] = None) -> str:
        """Creates a new Bead (task) file and commits it."""
        case_dir = self.base_dir / case_id
        if not case_dir.exists():
            return f"Error: Investigation {case_id} not found. Create it first."

        # Generate a Bead ID (simple counter based on existing beads to keep it readable, or random)
        # Using timestamp-based suffix for uniqueness
        bead_suffix = datetime.now().strftime("%H%M%S")
        bead_id = f"bead-{bead_suffix}"

        bead = Bead(
            id=bead_id,
            description=description,
            assigned_to=assigned_to,
            context=context or {}
        )

        bead_path = case_dir / f"{bead_id}.yaml"
        bead_path.write_text(bead.to_yaml())

        self._run_git(case_dir, ["add", str(bead_path.name)])
        self._run_git(case_dir, ["commit", "-m", f"Add bead {bead_id}: {description[:50]}"])

        return f"Created Bead {bead_id} assigned to {assigned_to}"

    def update_bead(self, case_id: str, bead_id: str, updates: Dict[str, Any]) -> str:
        """Updates an existing Bead and commits the change."""
        case_dir = self.base_dir / case_id
        if not case_dir.exists():
            return f"Error: Investigation {case_id} not found."

        bead_path = case_dir / f"{bead_id}.yaml"
        if not bead_path.exists():
            # Try finding it if user didn't provide extension
            bead_path = case_dir / bead_id
            if not bead_path.exists():
                 return f"Error: Bead {bead_id} not found in {case_id}."

        try:
            bead = Bead.from_yaml(bead_path.read_text())
        except Exception as e:
            return f"Error reading bead: {e}"

        # Apply updates
        data = bead.model_dump()
        for k, v in updates.items():
            if k in data:
                data[k] = v

        data['updated_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        updated_bead = Bead(**data)

        bead_path.write_text(updated_bead.to_yaml())

        # Format commit message
        changes = ", ".join(updates.keys())
        self._run_git(case_dir, ["add", str(bead_path.name)])
        self._run_git(case_dir, ["commit", "-m", f"Update bead {bead_id}: {changes}"])

        return f"Updated Bead {bead_id}. New status: {updated_bead.status}"

    def log_artifact(self, case_id: str, filename: str, content: str) -> str:
        """Saves an artifact (log, report, evidence) and commits it."""
        case_dir = self.base_dir / case_id
        if not case_dir.exists():
            return f"Error: Investigation {case_id} not found."

        file_path = case_dir / filename
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content)

        self._run_git(case_dir, ["add", "."]) # Add all, in case new dirs were made
        self._run_git(case_dir, ["commit", "-m", f"Log artifact: {filename}"])

        return f"Logged artifact {filename} to investigation {case_id}"

    def list_beads(self, case_id: str) -> str:
        """Lists all beads in an investigation."""
        case_dir = self.base_dir / case_id
        if not case_dir.exists():
            return f"Error: Investigation {case_id} not found."

        beads = []
        for f in case_dir.glob("bead-*.yaml"):
            try:
                b = Bead.from_yaml(f.read_text())
                beads.append(b)
            except:
                continue

        if not beads:
            return "No beads found."

        # Sort by ID
        beads.sort(key=lambda x: x.id)

        output = [f"Beads for Case {case_id}:"]
        for b in beads:
            output.append(f"- [{b.status}] {b.id}: {b.description} (Assigned: {b.assigned_to})")

        return "\n".join(output)
