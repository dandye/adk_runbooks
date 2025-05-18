import asyncio
import contextlib
from google.adk.agents import Agent

from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioServerParameters


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
  common_exit_stack = contextlib.AsyncExitStack()
  siem_tools, common_exit_stack = await asyncio.shield(MCPToolset.from_server(
    connection_params=StdioServerParameters(
    command='uv',
    args=[
        "--directory",
        "/Users/dandye/Projects/google-mcp-security/server/secops/secops_mcp",  # Corrected path
        "run",
        "--env-file",
        "/Users/dandye/Projects/google-mcp-security/.env",  # Corrected path (assuming .env is at project root)
        "server.py"
      ],
    ),
    async_exit_stack=common_exit_stack
  ))
  #siem_tools = make_tools_gemini_compatible(siem_tools)
  await asyncio.sleep(2)  # Give the first server time to stabilize
  soar_tools, common_exit_stack = await asyncio.shield(MCPToolset.from_server(
     connection_params=StdioServerParameters(
     command='uv',
     args=[
         "--directory",
         "/Users/dandye/Projects/google-mcp-security/server/secops-soar/secops_soar_mcp",  # Corrected path
         "run",
         "--env-file",
         "/Users/dandye/Projects/google-mcp-security/.env",
         "server.py",
         "--integrations",
         "CSV,GoogleChronicle,Siemplify,SiemplifyUtilities"
       ],
     ),
     #env={"PORT": "8082"},
     async_exit_stack=common_exit_stack
  ))
  #soar_tools = make_tools_gemini_compatible(soar_tools)

  persona_file_path = "/Users/dandye/Projects/adk_runbooks/rules-bank/personas/soc_analyst_tier_1.md"
  runbook_files = [
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/triage_alerts.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/close_duplicate_or_similar_cases.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/investgate_a_case_w_external_tools.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/group_cases.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/group_cases_v2.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/basic_ioc_enrichment.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/suspicious_login_triage.md",
    "/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guidelines/report_writing.md",
    #"/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/demo_soc_t1_siem_runbook.md",
    #"/Users/dandye/Projects/adk_runbooks/rules-bank/run_books/guidelines/demo_threat_intel_workflows.md",
  ]

  try:
    with open(persona_file_path, 'r') as f:
      persona_description = f.read()
  except FileNotFoundError:
    # Fallback or error handling if the persona file is not found
    persona_description = "Default CTI Researcher description: Responsible for threat intelligence."
    print(f"Warning: Persona file not found at {persona_file_path}. Using default description.")

  for runbook_file in runbook_files:
    try:
      with open(runbook_file, 'r') as f:
        runbook_content = f.read()
      persona_description += "\n\n" + runbook_content
    except FileNotFoundError:
      print(f"Warning: Runbook file not found at {runbook_file}. Skipping.")

  soc_analyst_tier1 = Agent(
      name="soc_analyst_tier1",
      model="gemini-2.5-pro-preview-05-06",
      description=persona_description,
      instruction="""You are a Tier 1 SOC Analyst.""",
      tools=[*siem_tools, *soar_tools],
  )
  return soc_analyst_tier1, common_exit_stack


agent_coroutine = get_agent()
#
## Export these for other modules to use
soc_analyst_tier1 = None
exit_stack = None
#
## Function to initialize the agent (to be called from the appropriate place in your application)
async def initialize():
    global soc_analyst_tier1, exit_stack
    try:
      soc_analyst_tier1, exit_stack = await agent_coroutine
      return soc_analyst_tier1, exit_stack
    except Exception as e:
      # Log the error or handle it appropriately
      print(f"Error initializing agent: {e}")
      # You might want to clean up any partially initialized resources
      if exit_stack:
          await exit_stack.aclose()
      raise  # Re-raise the exception to let callers know initialization failed