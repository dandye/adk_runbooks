import asyncio

from google.adk.agents import Agent

from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioServerParameters


async def get_tools_async():
  tools, exit_stack = await MCPToolset.from_server(
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
    )
  )
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

  soc_analyst_tier1 = Agent(
      name="soc_analyst_tier1",
      model="gemini-2.0-flash",
      description="SOC Analyst Tier 1",
      instruction="""
      You are a Tier 1 SOC Analyst.
      """,
      tools=compatible_tools,
  )
  return soc_analyst_tier1, exit_stack

agent_coroutine = get_agent()

# Export these for other modules to use
soc_analyst_tier1 = None
exit_stack = None

# Function to initialize the agent (to be called from the appropriate place in your application)
async def initialize():
    global soc_analyst_tier1, exit_stack
    soc_analyst_tier1, exit_stack = await agent_coroutine
    return soc_analyst_tier1, exit_stack

## Use asyncio.run to execute the async function
#def initialize_agent():
#    return asyncio.run(get_agent())
#
## Now call the synchronous wrapper function
#soc_analyst_tier1, exit_stack = initialize_agent()
