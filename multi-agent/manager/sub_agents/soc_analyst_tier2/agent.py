import asyncio

from google.adk.agents import Agent

from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioServerParameters


async def get_tools_async():
  #siem_tools, exit_stack = await MCPToolset.from_server(
  #  connection_params=StdioServerParameters(
  #  command='uv',
  #  args=[
  #      "--directory",
  #      "/Users/dandye/Projects/google-mcp-security/server/secops/secops_mcp",  # Corrected path
  #      "run",
  #      "--env-file",
  #      "/Users/dandye/Projects/google-mcp-security/.env",  # Corrected path (assuming .env is at project root)
  #      "server.py"
  #    ],
  #  )
  #)
  #tools = siem_tools
  soar_tools, exit_stack = await MCPToolset.from_server(
    connection_params=StdioServerParameters(
    command='uv',
    args=[
        "--directory",
        "/Users/dandye/Projects/google-mcp-security/server/secops-soar/secops_soar_mcp",  # Corrected path
        "run",
        "--env-file",
        "/Users/dandye/Projects/google-mcp-security/.env",
        "server.py",
        #"--integrations",  # doesn't work in ADK?
        #"CSV,GoogleChronicle,Siemplify,SiemplifyUtilities"
      ],
    )
  )
  #tools.extend(soar_tools)
  tools = soar_tools
  return tools, exit_stack

def make_tools_gemini_compatible(tools):
  """
  This function makes the schema compatible with Gemini/Vertex AI API
  It is only needed when API used is Gemini and model is other than 2.5 models
  It is however needed for ALL models when API used is VertexAI
  """
  for tool in tools:
    if hasattr(tool, 'mcp_tool') and hasattr(tool.mcp_tool, 'inputSchema') and tool.mcp_tool.inputSchema:
      if "properties" in tool.mcp_tool.inputSchema:
          for prop_name in list(tool.mcp_tool.inputSchema["properties"].keys()): # Use list() for safe iteration
            if "anyOf" in tool.mcp_tool.inputSchema["properties"][prop_name]:
              # Ensure 'anyOf' list is not empty and first item has 'type' or 'items'
              if tool.mcp_tool.inputSchema["properties"][prop_name]["anyOf"]:
                first_any_of_item = tool.mcp_tool.inputSchema["properties"][prop_name]["anyOf"][0]
                if first_any_of_item.get("type") == "array" and "items" in first_any_of_item and "type" in first_any_of_item["items"]:
                  tool.mcp_tool.inputSchema["properties"][prop_name]["type"] = first_any_of_item["items"]["type"]
                elif "type" in first_any_of_item:
                   tool.mcp_tool.inputSchema["properties"][prop_name]["type"] = first_any_of_item["type"]
                # else: could add a warning or skip if type cannot be determined
              tool.mcp_tool.inputSchema["properties"][prop_name].pop("anyOf", None) # Use pop with default
  return tools

async def get_agent():
  tools, exit_stack = await get_tools_async()
  compatible_tools = make_tools_gemini_compatible(list(tools)) # Ensure tools is a list and then process

  persona_file_path = "/Users/dandye/Projects/adk_runbooks/rules-bank/personas/soc_analyst_tier_2.md"
  runbook_files = [
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/investigate_a_gti_collection_id.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/proactive_threat_hunting_based_on_gti_campain_or_actor.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/compare_gti_collection_to_iocs_and_events.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/ioc_threat_hunt.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/apt_threat_hunt.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/deep_dive_ioc_analysis.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/malware_triage.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guidelines/threat_intel_workflows.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guidelines/report_writing.md",
    # `case_event_timeline_and_process_analysis.md`, `create_an_investigation_report.md`, `phishing_response.md`, or `ransomware_response.md`.
  ]

  try:
    with open(persona_file_path, 'r') as f:
      persona_description = f.read()
  except FileNotFoundError:
    # Fallback or error handling if the persona file is not found
    persona_description = "Default Tier 2 SOC Analyst."
    print(f"Warning: Persona file not found at {persona_file_path}. Using default description.")

  for runbook_file in runbook_files:
    try:
      with open(runbook_file, 'r') as f:
        runbook_content = f.read()
      persona_description += "\n\n" + runbook_content
    except FileNotFoundError:
      print(f"Warning: Runbook file not found at {runbook_file}. Skipping.")


  soc_analyst_tier1 = Agent(
      name="soc_analyst_tier2",
      model="gemini-2.0-flash",
      description=persona_description,
      instruction="""
      You are a Tier 2 SOC Analyst.
      """,
      tools=compatible_tools,
  )
  return soc_analyst_tier1, exit_stack

agent_coroutine = get_agent()

# Export these for other modules to use
soc_analyst_tier2 = None
exit_stack = None

# Function to initialize the agent (to be called from the appropriate place in your application)
async def initialize():
    global soc_analyst_tier2, exit_stack
    soc_analyst_tier2, exit_stack = await agent_coroutine
    return soc_analyst_tier2, exit_stack
