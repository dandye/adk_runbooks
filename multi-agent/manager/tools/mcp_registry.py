"""Centralized MCP Tool Registry and Progressive Discovery Engine."""

import asyncio
from dataclasses import dataclass, field
import inspect
import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)


def _extract_schema_from_callable(func: Any) -> dict[str, Any]:
    """Extract JSON Schema from a Python callable's signature."""
    if not callable(func):
        return {}
    try:
        sig = inspect.signature(func)
    except Exception:
        return {}

    properties: dict[str, Any] = {}
    required: list[str] = []
    for param_name, param in sig.parameters.items():
        if param_name in ("self", "cls", "args", "kwargs"):
            continue
        if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue

        ann = param.annotation
        json_type = "string"
        if ann is int or "int" in str(ann).lower():
            json_type = "integer"
        elif ann is float or "float" in str(ann).lower():
            json_type = "number"
        elif ann is bool or "bool" in str(ann).lower():
            json_type = "boolean"
        elif "list" in str(ann).lower():
            json_type = "array"
        elif "dict" in str(ann).lower():
            json_type = "object"

        prop_spec: dict[str, Any] = {"type": json_type}
        if param.default is not inspect.Parameter.empty:
            prop_spec["default"] = param.default
        else:
            required.append(param_name)
        properties[param_name] = prop_spec

    if not properties:
        return {"type": "object", "properties": {}}
    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
    }
    if required:
        schema["required"] = required
    return schema


@dataclass
class MCPToolMetadata:
    """Metadata representing an MCP tool discovered across connected servers."""

    name: str
    server: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)
    executor: Any | None = None
    version: str = "1.0.0"


class MCPToolRegistry:
    """Central registry for indexing, discovering, and executing MCP security tools."""

    def __init__(self):
        self._tools: dict[str, MCPToolMetadata] = {}

    def register_tool(self, metadata: MCPToolMetadata) -> None:
        """Indexes tool under original name, kebab-case, snake_case, and prefix aliases."""
        norm_name = metadata.name.strip()
        self._tools[norm_name] = metadata

        # Register alternative kebab-case format
        alt_hyphen = norm_name.replace("_", "-")
        self._tools[alt_hyphen] = metadata

        # Register alternative snake_case format
        alt_underscore = norm_name.replace("-", "_")
        self._tools[alt_underscore] = metadata

        # Register prefix-normalized aliases (e.g. secops-mcp_X -> secops_X, X; soar-mcp_X -> soar_X, secops-soar_X, secops_X, X)
        for prefix in ("secops-mcp_", "secops_mcp_", "soar-mcp_", "soar_mcp_", "gti-mcp_", "gti_mcp_", "secops-soar_", "secops_soar_"):
            if norm_name.startswith(prefix):
                base_tool_name = norm_name[len(prefix):]
                for alias in (
                    base_tool_name,
                    f"secops_{base_tool_name}",
                    f"soar_{base_tool_name}",
                    f"secops-soar_{base_tool_name}",
                    f"secops_soar_{base_tool_name}",
                    f"gti_{base_tool_name}",
                ):
                    if alias not in self._tools:
                        self._tools[alias] = metadata
                        self._tools[alias.replace("_", "-")] = metadata

    def register_mcp_toolset(self, toolset: Any, server_name: str) -> int:
        """Reflects and extracts tool definitions from an ADK McpToolset or tool collection."""
        registered_count = 0
        extracted_tools: list[Any] = []

        if hasattr(toolset, "get_tools") and callable(getattr(toolset, "get_tools")):
            if inspect.iscoroutinefunction(toolset.get_tools):
                if hasattr(toolset, "_offline_tools") and isinstance(toolset._offline_tools, (list, tuple)):
                    extracted_tools.extend(toolset._offline_tools)
            else:
                try:
                    tools_list = toolset.get_tools()
                    if inspect.iscoroutine(tools_list):
                        tools_list.close()
                    elif isinstance(tools_list, (list, tuple)):
                        extracted_tools.extend(tools_list)
                except Exception as e:
                    logger.warning("Error calling get_tools() on %s toolset: %s", server_name, e)
        elif hasattr(toolset, "tools") and isinstance(toolset.tools, (list, tuple)):
            extracted_tools.extend(toolset.tools)
        elif isinstance(toolset, (list, tuple)):
            extracted_tools.extend(toolset)
        elif toolset is not None:
            extracted_tools.append(toolset)

        seen_names: set[str] = set()
        for tool in extracted_tools:
            name = getattr(tool, "name", None)
            description = getattr(tool, "description", "") or ""
            input_schema: dict[str, Any] = {}

            if hasattr(tool, "_get_declaration") and callable(getattr(tool, "_get_declaration")):
                try:
                    decl = tool._get_declaration()
                    if not name and hasattr(decl, "name"):
                        name = decl.name
                    if not description and hasattr(decl, "description"):
                        description = decl.description or ""
                    if hasattr(decl, "parameters_json_schema") and decl.parameters_json_schema:
                        input_schema = decl.parameters_json_schema
                    elif hasattr(decl, "parameters") and decl.parameters:
                        input_schema = decl.parameters
                except Exception as e:
                    logger.debug("Could not inspect declaration for tool %s: %s", name, e)

            if not description and callable(tool):
                description = inspect.getdoc(tool) or ""

            if not input_schema:
                if hasattr(tool, "input_schema") and isinstance(tool.input_schema, dict):
                    input_schema = tool.input_schema
                elif hasattr(tool, "parameters") and isinstance(tool.parameters, dict):
                    input_schema = tool.parameters
                elif callable(tool):
                    input_schema = _extract_schema_from_callable(tool)

            if not name:
                name = getattr(tool, "__name__", str(tool))

            if name and name not in seen_names:
                seen_names.add(name)
                meta = MCPToolMetadata(
                    name=name,
                    server=server_name,
                    description=str(description).strip(),
                    input_schema=input_schema if isinstance(input_schema, dict) else {},
                    executor=tool,
                )
                self.register_tool(meta)
                registered_count += 1

        return registered_count

    def get_tool(self, tool_name: str) -> MCPToolMetadata | None:
        """Retrieve tool metadata by name with whitespace/format normalization."""
        if not tool_name:
            return None
        norm_name = tool_name.strip()
        if norm_name in self._tools:
            return self._tools[norm_name]
        alt_hyphen = norm_name.replace("_", "-")
        if alt_hyphen in self._tools:
            return self._tools[alt_hyphen]
        alt_underscore = norm_name.replace("-", "_")
        if alt_underscore in self._tools:
            return self._tools[alt_underscore]
        return None

    def search_tools(self, query: str = "", server: str = "") -> list[dict[str, str]]:
        """Search available tools by keyword query and/or server filter."""
        import re

        seen_names: set[str] = set()
        matched: list[dict[str, str]] = []
        q = query.strip().lower()
        s = server.strip().lower()
        q_tokens = [
            tok for tok in re.split(r"[\s_\-]+", q)
            if tok and tok not in ("mcp", "tool", "tools")
        ]

        for meta in self._tools.values():
            if meta.name in seen_names:
                continue
            seen_names.add(meta.name)

            if s and s != meta.server.lower() and s not in meta.server.lower():
                continue

            if q:
                haystack = f"{meta.name} {meta.server} {meta.description}".lower()
                in_exact = (
                    q in meta.name.lower()
                    or q in meta.description.lower()
                    or q in meta.server.lower()
                )
                in_tokens = bool(q_tokens) and all(tok in haystack for tok in q_tokens)
                if not (in_exact or in_tokens):
                    continue

            matched.append({
                "name": meta.name,
                "server": meta.server,
                "description": meta.description,
            })

        return sorted(matched, key=lambda x: (x["server"], x["name"]))

    def get_tool_schema(self, tool_name: str) -> dict[str, Any] | None:
        """Returns structured parameter documentation and JSON Schema for a tool."""
        meta = self.get_tool(tool_name)
        if not meta:
            return None
        return {
            "name": meta.name,
            "server": meta.server,
            "description": meta.description,
            "input_schema": meta.input_schema,
        }

    def get_compact_catalog(self, server: str = "") -> str:
        """Generates a compact Markdown list of tools for prompt injection."""
        tools = self.search_tools(query="", server=server)
        if not tools:
            return ""

        lines = [f"- **{t['name']}** ({t['server']}): {t['description']}" for t in tools]
        return "\n".join(lines)

    def execute_tool(self, tool_name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Validates arguments and executes the target MCP tool."""
        if arguments is None:
            arguments = {}

        meta = self.get_tool(tool_name)
        if not meta:
            raise ValueError(f"Tool '{tool_name}' not found in registry.")

        # Validate required arguments against input_schema
        if meta.input_schema and isinstance(meta.input_schema, dict):
            required = meta.input_schema.get("required", [])
            if isinstance(required, list):
                for req_param in required:
                    if req_param not in arguments:
                        raise ValueError(f"Missing required argument '{req_param}' for tool '{meta.name}'.")

        if meta.executor is None:
            raise RuntimeError(f"No executor registered for tool '{meta.name}'.")

        executor = meta.executor
        if hasattr(executor, "func") and callable(getattr(executor, "func")):
            executor = executor.func

        if inspect.iscoroutinefunction(executor):
            return executor(**arguments)
        elif callable(executor):
            try:
                return executor(**arguments)
            except TypeError as exc:
                sig = inspect.signature(executor)
                params = list(sig.parameters.values())
                has_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)
                if not has_var_kw:
                    accepted = {
                        k: v for k, v in arguments.items() if k in sig.parameters
                    }
                    if len(accepted) != len(arguments):
                        return executor(**accepted)
                if len(params) == 1 and params[0].name in ("args", "arguments", "payload", "input_data"):
                    return executor(arguments)
                raise ValueError(
                    f"Invalid arguments for tool '{meta.name}': {exc}"
                ) from exc
        elif hasattr(executor, "run_async") and callable(getattr(executor, "run_async")):
            return executor.run_async(arguments)
        else:
            raise RuntimeError(f"Executor for tool '{meta.name}' is not callable.")
