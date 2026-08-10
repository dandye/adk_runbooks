import os
import yaml
import logging
from typing import Optional

try:
    from google.adk.a2a.utils.agent_to_a2a import to_a2a
    from a2a.types import AgentCard, AgentSkill, AgentCapabilities
except ImportError:
    logging.warning("A2A library not found. A2A features will be unavailable.")
    to_a2a = None
    AgentCard = None
    AgentSkill = None
    AgentCapabilities = None

def get_a2a_app_from_config(agent, yaml_config_path: str, host: str = "0.0.0.0", port: int = 8000, protocol: str = "http"):
    """
    Creates an A2A Starlette application for the given agent using a YAML configuration file.

    Args:
        agent: The initialized ADK Agent instance.
        yaml_config_path: Path to the YAML configuration file defining the agent card properties.
        host: The host for the A2A service (default: "0.0.0.0").
        port: The port for the A2A service (default: 8000).
        protocol: The protocol for the A2A service (default: "http").

    Returns:
        Starlette: The configured A2A application.
    """
    if not to_a2a:
        raise ImportError("A2A library is required to use this feature.")

    try:
        with open(yaml_config_path, 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        logging.error(f"Configuration file not found at {yaml_config_path}")
        raise

    # Construct AgentSkill based on YAML configuration
    # Combine expertise areas and delegation triggers as tags
    tags = config.get('expertise_areas', []) + config.get('delegation_triggers', [])
    # Filter duplicates and ensure strings
    tags = list(set([str(tag) for tag in tags]))

    skill = AgentSkill(
        id=config.get('agent_name', agent.name),
        name=config.get('display_name', agent.name),
        description=config.get('description', agent.description or "No description provided"),
        tags=tags,
        input_modes=['text/plain'],
        output_modes=['text/plain'],
        examples=None
    )

    rpc_url = f"{protocol}://{host}:{port}"

    card = AgentCard(
        name=config.get('agent_name', agent.name),
        description=config.get('description', agent.description or "No description provided"),
        version="1.0.0",
        skills=[skill],
        capabilities=AgentCapabilities(),
        url=rpc_url,
        default_input_modes=['text/plain'],
        default_output_modes=['text/plain'],
        supports_authenticated_extended_card=False
    )

    return to_a2a(
        agent=agent,
        host=host,
        port=port,
        protocol=protocol,
        agent_card=card
    )
