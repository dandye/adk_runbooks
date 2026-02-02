from typing import Dict, Any, Optional
from ..utils.instrumentation import instrument_tool
from ..utils.gastown import GasTownMayor

# Initialize single instance of Mayor to manage paths
_mayor = GasTownMayor()

@instrument_tool
def create_case_worktree(case_id: str) -> str:
    """
    Initializes a new persistent Git-backed workspace for a SOC investigation.

    Use this tool at the START of any new investigation to establish the 'Town'
    and enable the 'Propulsion Principle' (persistence).

    Args:
        case_id: A unique identifier for the case (e.g., "CASE-123", "alert-555").

    Returns:
        Status message indicating success or failure.
    """
    return _mayor.create_investigation(case_id)

@instrument_tool
def create_bead(case_id: str, description: str, assigned_to: str, context: Optional[str] = None) -> str:
    """
    Delegates a task by creating a 'Bead' (a structured task file tracked in Git).

    Use this to assign work to sub-agents or to track your own investigation steps.

    Args:
        case_id: The identifier of the active investigation.
        description: A clear description of the task to be performed.
        assigned_to: The name of the agent responsible (e.g., "soc_analyst_tier1").
        context: Optional extra details, JSON string or plain text.

    Returns:
        Confirmation string with the new Bead ID.
    """
    # Simple handling of context if it's a string, wrap it in a dict
    ctx_dict = {}
    if context:
        ctx_dict["info"] = context

    return _mayor.create_bead(case_id, description, assigned_to, ctx_dict)

@instrument_tool
def update_bead(case_id: str, bead_id: str, status: str, notes: Optional[str] = None) -> str:
    """
    Updates the status of a Bead (task).

    Args:
        case_id: The identifier of the active investigation.
        bead_id: The ID of the bead to update (e.g., "bead-123456").
        status: The new status (TODO, IN_PROGRESS, DONE, BLOCKED).
        notes: Optional notes to add to the task context/logs.

    Returns:
        Status message.
    """
    updates = {"status": status}
    if notes:
        updates["notes"] = notes

    return _mayor.update_bead(case_id, bead_id, updates)

@instrument_tool
def log_work(case_id: str, filename: str, content: str) -> str:
    """
    Saves work artifacts (logs, evidence, thoughts) to the investigation repo.

    This invokes the 'Propulsion Principle', ensuring work is permanently recorded
    in the git history.

    Args:
        case_id: The identifier of the active investigation.
        filename: Name of the file to save (e.g. "query_results.json", "analysis.md").
        content: The text content to save.

    Returns:
        Status message.
    """
    return _mayor.log_artifact(case_id, filename, content)

@instrument_tool
def list_beads(case_id: str) -> str:
    """
    Lists all Beads (tasks) for a given investigation case.

    Args:
        case_id: The identifier of the active investigation.

    Returns:
        A list of beads with their statuses and assignments.
    """
    return _mayor.list_beads(case_id)
