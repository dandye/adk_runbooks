from google.adk.agents.remote_a2a_agent import RemoteA2aAgent

def get_agent(tools):
  """
  Returns a RemoteA2aAgent configured to talk to a local A2A service.

  This assumes that an A2A service (e.g., soc_analyst_tier1 running as A2A)
  is available at http://localhost:8001.
  """
  # The RemoteA2aAgent takes an 'agent_card' argument which can be a URL string
  # pointing to the A2A service's card endpoint.
  # The standard A2A implementation usually exposes the card at the root or /a2a.json
  # We will point to the root URL of the service.
  service_url = "http://localhost:8001/"

  agent = RemoteA2aAgent(
      name="remote_assistant",
      agent_card=service_url,
      # Remote agents don't use local tools directly, but we accept them for signature compatibility
  )

  # Add a description so the manager knows what this agent does.
  # In a real scenario, this would be fetched from the remote card,
  # but setting it here helps with initial planning before connection.
  agent.description = "A remote assistant agent available via A2A interface. Can handle general queries or tasks delegated to the remote service."

  return agent

def get_a2a_app(tools, host="0.0.0.0", port=8000):
    """
    Creates an A2A app for this agent (proxying the remote one).
    For a remote agent, this might just expose the same interface again.
    """
    from ...utils.a2a import get_a2a_app_from_config
    # We can create a simple card for this proxy
    # For now, we'll reuse the logic but we need a config file.
    # Let's assume we don't need to expose the remote agent *as* an A2A service again immediately in this demo.
    # But to satisfy the pattern, we could return a simple app.
    raise NotImplementedError("Exposing a RemoteA2aAgent as an A2A service is not yet fully configured.")
