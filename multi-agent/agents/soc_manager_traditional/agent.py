"""SOC Manager Traditional Agent for ADK Web."""

import sys
import os
from pathlib import Path

# Add the parent directories to Python path
current_dir = Path(__file__).resolve().parent
multi_agent_dir = current_dir.parent.parent
manager_dir = multi_agent_dir / "manager"

sys.path.insert(0, str(multi_agent_dir))
sys.path.insert(0, str(manager_dir))

# Import the traditional deferred initialization agent
from manager.agent import DeferredInitializationAgent, initialize_actual_manager_agent

# Create the agent instance for ADK discovery
# ADK looks for 'root_agent' variable
root_agent = DeferredInitializationAgent("manager", initialize_actual_manager_agent)