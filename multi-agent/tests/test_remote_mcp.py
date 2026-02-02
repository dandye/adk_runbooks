import os
import unittest
import google.auth
from google.auth.transport.requests import Request
from google.adk.tools.mcp_tool import MCPToolset, StreamableHTTPConnectionParams

# Scopes for Chronicle
SCOPES = ["https://www.googleapis.com/auth/chronicle"]

class TestRemoteMCP(unittest.TestCase):

    def setUp(self):
        self.project_id = os.environ.get("CHRONICLE_PROJECT_ID")
        self.customer_id = os.environ.get("CHRONICLE_CUSTOMER_ID")
        self.region = os.environ.get("CHRONICLE_REGION")

        if not all([self.project_id, self.customer_id, self.region]):
            self.skipTest("Missing environment variables: CHRONICLE_PROJECT_ID, CHRONICLE_CUSTOMER_ID, CHRONICLE_REGION")

    def get_access_token(self):
        creds, _ = google.auth.default(scopes=SCOPES)
        auth_req = Request()
        creds.refresh(auth_req)
        return creds.token

    def test_list_soar_cases(self):
        # Construct URL
        # URL pattern: https://chronicle.{region}.rep.googleapis.com/mcp
        url = f"https://chronicle.{self.region}.rep.googleapis.com/mcp"

        print(f"Connecting to remote MCP server (region: {self.region})")

        # Configure Toolset
        try:
            toolset = MCPToolset(
                connection_params=StreamableHTTPConnectionParams(
                    url=url,
                    headers={
                        "Authorization": f"Bearer {self.get_access_token()}",
                        "Accept": "text/event-stream",
                        "x-goog-user-project": self.project_id
                    }
                )
            )
        except Exception as e:
            self.fail(f"Failed to initialize MCPToolset: {e}")

        tool_name = "list_cases"

        # Arguments for the tool
        # Using context as per docs
        args = {
            "project_id": self.project_id,
            "customer_id": self.customer_id,
            "region": self.region,
            "page_size": 3
        }

        try:
            # MCPToolset is likely an iterable of tools or has a method to get them.
            # We assume it behaves like a list of tools.
            found_tool = None

            # Since we can't inspect the implementation, we iterate if possible.
            # If not iterable, we might need to check how to access tools.
            # Assuming standard ADK pattern where toolset is a collection of tools.

            # We look for the tool by name
            target_tool_name = "list_cases"

            # We need to access the tools.
            # If toolset is not iterable, this will raise TypeError
            tools_list = list(toolset)

            print(f"Found {len(tools_list)} tools.")

            for tool in tools_list:
                # tool.name is expected to be the tool name
                if tool.name == target_tool_name:
                    found_tool = tool
                    break

            if not found_tool:
                # Try to search for similar
                for tool in tools_list:
                    if "case" in tool.name and "list" in tool.name:
                        found_tool = tool
                        print(f"Using alternative tool: {tool.name}")
                        break

            if not found_tool:
                self.fail(f"Tool '{target_tool_name}' not found in remote MCP server.")

            print(f"Calling tool {found_tool.name} to list 3 cases...")

            # Call the tool
            result = found_tool(**args)

            # Verify result
            self.assertIsNotNone(result)

            # We avoid printing the full result to avoid leaking sensitive case data if any.
            # But we can check if it's a list or dict and print its type/size.
            print(f"Tool returned result of type: {type(result)}")

            if isinstance(result, (list, tuple)):
                print(f"Number of items: {len(result)}")
            elif isinstance(result, str):
                print(f"Result length: {len(result)}")

            print("Test completed successfully.")

        except Exception as e:
            self.fail(f"Tool execution failed: {e}")

if __name__ == '__main__':
    unittest.main()
