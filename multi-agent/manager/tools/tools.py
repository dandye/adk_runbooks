from datetime import datetime
import asyncio
import contextlib

from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioServerParameters


def get_current_time() -> dict:
    """
    Get the current time in the format YYYYMMDD_HHMMSS
    """
    return {
        "current_time": datetime.now().strftime("%Y%m%d_%H%M%S"),
    }

def write_report(report_name: str, report_contents: str):
    """Write a report to a file.

    Args:
        report_name: The name of the report.
        report_contents: The contents of the report.

    """
    now = get_current_time()["current_time"]
    with open(f"../reports/{report_name}_{now}.md", "w") as f:
        f.write(f"{report_contents}")

async def get_agent_tools():
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
     async_exit_stack=common_exit_stack
  ))
  await asyncio.sleep(2)  # Give the first server time to stabilize
  gti_tools, common_exit_stack = await MCPToolset.from_server(
    connection_params=StdioServerParameters(
    command='uv',
    args=[
        "--directory",
        "/Users/dandye/Projects/google-mcp-security/server/gti/gti_mcp",
        "run",
        "--env-file",
        "/Users/dandye/Projects/google-mcp-security/.env",
        "server.py"
      ],
    ),
    async_exit_stack=common_exit_stack
  )

  return (*siem_tools, *soar_tools, *gti_tools), common_exit_stack
