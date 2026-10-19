"""Offline-resilient MCPToolset and canonical SIEM/SOAR/GTI FunctionTool specs."""

import inspect
import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from google.adk.tools import FunctionTool
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset
from google.adk.tools.mcp_tool.mcp_toolset import StdioConnectionParams

from .mcp_registry import MCPToolMetadata
from .mcp_registry import MCPToolRegistry
from .mcp_registry import _extract_schema_from_callable

logger = logging.getLogger(__name__)


class OfflineResilientMCPToolset(MCPToolset):
  """MCPToolset that uses offline FunctionTool declarations in test/offline environments.

  When `.env` is present in live execution, connects to the real MCP server.
  If `ADK_STRICT_MCP_CONNECT=1` is set, connection failures raise immediately;
  otherwise a warning is logged before falling back to local declarations.
  """

  def __init__(
      self,
      *,
      connection_params: StdioConnectionParams,
      tool_name_prefix: str | None = None,
      env_file_path: Path | None = None,
      offline_tools: list[BaseTool] | None = None,
  ):
    super().__init__(
        connection_params=connection_params,
        tool_name_prefix=tool_name_prefix,
    )
    self._env_file_path = env_file_path
    self._offline_tools = list(offline_tools or [])

  async def get_tools(self, readonly_context: Any = None) -> list[BaseTool]:
    if (
        os.environ.get("PYTEST_CURRENT_TEST")
        or os.environ.get("ADK_OFFLINE_MCP_MOCKS") == "1"
        or (
            self._env_file_path is not None and not self._env_file_path.exists()
        )
    ):
      return list(self._offline_tools)
    try:
      return await super().get_tools(readonly_context)
    except Exception as exc:
      if os.environ.get("ADK_STRICT_MCP_CONNECT") == "1":
        raise
      logger.warning(
          "MCP server connection failed for prefix=%s (%s: %s); falling back to offline tool declarations.",
          self.tool_name_prefix,
          type(exc).__name__,
          exc,
      )
      return list(self._offline_tools)


def build_canonical_mcp_tools(
    server: str,
    registry: MCPToolRegistry,
) -> list[BaseTool]:
  """Build lightweight FunctionTool representations of canonical SIEM, SOAR, and GTI MCP tools."""
  specs: dict[str, list[tuple[str, str, Callable[..., Any]]]] = {
      "siem": [
          (
              "search_security_events",
              "Search Chronicle SIEM UDM security events using natural language or UDM filter.",
              lambda text="", query="", hours_back=168, max_events=50: {
                  "status": "success",
                  "server": "siem",
                  "events_matched": 1,
                  "query": query or text,
              },
          ),
          (
              "lookup_entity",
              "Look up an IP, domain, hash, or user entity in Chronicle SIEM.",
              lambda entity_value="", hours_back=168: {
                  "status": "success",
                  "server": "siem",
                  "entity_value": entity_value,
                  "summary": f"Entity {entity_value} inspected in Chronicle SIEM.",
              },
          ),
          (
              "get_security_alerts",
              "Retrieve security alerts from Chronicle SIEM.",
              lambda query="", max_alerts=25: {
                  "status": "success",
                  "server": "siem",
                  "alerts": [],
              },
          ),
          (
              "get_ioc_matches",
              "Fetch IOC matches from Chronicle SIEM.",
              lambda hours_back=72, max_matches=25: {
                  "status": "success",
                  "server": "siem",
                  "ioc_matches": [],
              },
          ),
          (
              "list_security_rules",
              "List YARA-L detection rules in Chronicle SIEM.",
              lambda query="": {
                  "status": "success",
                  "server": "siem",
                  "rules": [],
              },
          ),
          (
              "get_detection_rule",
              "Retrieve a specific YARA-L detection rule by rule_id.",
              lambda rule_id="": {
                  "status": "success",
                  "server": "siem",
                  "rule_id": rule_id,
              },
          ),
          (
              "get_threat_intel",
              "Query SecOps threat intelligence context.",
              lambda query="": {
                  "status": "success",
                  "server": "siem",
                  "summary": f"Threat intel summary for {query}",
              },
          ),
      ],
      "soar": [
          (
              "get_case_full_details",
              "Retrieve full details for a SOAR case including alerts and insights.",
              lambda case_id="": {
                  "status": "success",
                  "server": "soar",
                  "case_id": case_id,
              },
          ),
          (
              "post_case_comment",
              "Post an investigative comment to a SOAR case wall.",
              lambda case_id="", comment="": {
                  "status": "success",
                  "server": "soar",
                  "case_id": case_id,
                  "comment": comment,
              },
          ),
          (
              "list_cases",
              "List active SOAR cases.",
              lambda limit=25: {
                  "status": "success",
                  "server": "soar",
                  "cases": [],
              },
          ),
          (
              "list_alerts_by_case",
              "List alerts associated with a SOAR case.",
              lambda case_id="": {
                  "status": "success",
                  "server": "soar",
                  "case_id": case_id,
                  "alerts": [],
              },
          ),
          (
              "list_events_by_alert",
              "List UDM events associated with a SOAR alert.",
              lambda case_id="", alert_id="": {
                  "status": "success",
                  "server": "soar",
                  "case_id": case_id,
                  "alert_id": alert_id,
                  "events": [],
              },
          ),
          (
              "get_entities_by_alert_group_identifiers",
              "Retrieve entities linked to SOAR alert group identifiers.",
              lambda case_id="", alert_group_identifiers=None: {
                  "status": "success",
                  "server": "soar",
                  "case_id": case_id,
                  "entities": [],
              },
          ),
          (
              "change_case_priority",
              "Update the priority of a SOAR case.",
              lambda case_id="", priority="High": {
                  "status": "success",
                  "server": "soar",
                  "case_id": case_id,
                  "priority": priority,
              },
          ),
          (
              "get_case_settings_root_causes",
              "Retrieve configured SOAR case closure root causes.",
              lambda: {
                  "status": "success",
                  "server": "soar",
                  "root_causes": ["Benign", "True Positive", "Duplicate"],
              },
          ),
          (
              "siemplify_close_case",
              "Close a SOAR case with a reason and root cause.",
              lambda case_id="", reason="Resolved", root_cause="Benign", comment="": {
                  "status": "closed",
                  "server": "soar",
                  "case_id": case_id,
              },
          ),
          (
              "siemplify_close_alert",
              "Close an individual SOAR alert inside a case.",
              lambda case_id="", alert_group_identifier="", reason="Resolved", root_cause="Benign": {
                  "status": "closed",
                  "server": "soar",
                  "case_id": case_id,
              },
          ),
          (
              "siemplify_get_similar_cases",
              "Find similar historical SOAR cases for deduplication and grouping.",
              lambda case_id="", days_back=7: {
                  "status": "success",
                  "server": "soar",
                  "similar_cases": [],
              },
          ),
          (
              "google_chronicle_get_rule_details",
              "Fetch Chronicle rule details via SOAR integration.",
              lambda case_id="", rule_id="": {
                  "status": "success",
                  "server": "soar",
                  "rule_id": rule_id,
              },
          ),
          (
              "google_chronicle_get_detection_details",
              "Fetch Chronicle detection details via SOAR integration.",
              lambda case_id="", detection_id="": {
                  "status": "success",
                  "server": "soar",
                  "detection_id": detection_id,
              },
          ),
          (
              "google_chronicle_list_events",
              "List Chronicle events via SOAR integration.",
              lambda case_id="": {
                  "status": "success",
                  "server": "soar",
                  "events": [],
              },
          ),
          (
              "google_chronicle_add_values_to_reference_list",
              "Add IOC values to a Chronicle Reference List for containment.",
              lambda case_id="", reference_list_name="", values="": {
                  "status": "success",
                  "server": "soar",
                  "reference_list_name": reference_list_name,
              },
          ),
      ],
      "gti": [
          (
              "get_ip_address_report",
              "Retrieve VirusTotal / GTI reputation report for an IP address.",
              lambda ip_address="": {
                  "status": "success",
                  "server": "gti",
                  "ip_address": ip_address,
                  "verdict": "clean",
              },
          ),
          (
              "get_domain_report",
              "Retrieve VirusTotal / GTI reputation report for a domain.",
              lambda domain="": {
                  "status": "success",
                  "server": "gti",
                  "domain": domain,
                  "verdict": "clean",
              },
          ),
          (
              "get_file_report",
              "Retrieve VirusTotal / GTI reputation report for a file hash.",
              lambda hash="": {
                  "status": "success",
                  "server": "gti",
                  "hash": hash,
                  "verdict": "malicious",
              },
          ),
          (
              "get_file_behavior_summary",
              "Retrieve sandbox behavioral summary for a file hash from GTI.",
              lambda hash="": {
                  "status": "success",
                  "server": "gti",
                  "hash": hash,
                  "behaviors": [],
              },
          ),
          (
              "get_url_report",
              "Retrieve VirusTotal / GTI reputation report for a URL.",
              lambda url="": {
                  "status": "success",
                  "server": "gti",
                  "url": url,
                  "verdict": "clean",
              },
          ),
          (
              "get_collection_report",
              "Retrieve GTI threat intelligence collection report.",
              lambda collection_id="": {
                  "status": "success",
                  "server": "gti",
                  "collection_id": collection_id,
              },
          ),
          (
              "get_collection_timeline_events",
              "Retrieve timeline events for a GTI collection.",
              lambda collection_id="": {
                  "status": "success",
                  "server": "gti",
                  "collection_id": collection_id,
                  "events": [],
              },
          ),
          (
              "get_collection_mitre_tree",
              "Retrieve MITRE ATT&CK TTP tree for a GTI collection.",
              lambda collection_id="": {
                  "status": "success",
                  "server": "gti",
                  "collection_id": collection_id,
              },
          ),
          (
              "get_entities_related_to_a_collection",
              "Retrieve IOC entities associated with a GTI collection.",
              lambda collection_id="", relationship_name="": {
                  "status": "success",
                  "server": "gti",
                  "collection_id": collection_id,
                  "entities": [],
              },
          ),
          (
              "get_entities_related_to_a_domain",
              "Retrieve entities related to a domain in GTI.",
              lambda domain="", relationship_name="": {
                  "status": "success",
                  "server": "gti",
                  "domain": domain,
                  "entities": [],
              },
          ),
          (
              "get_threat_intel",
              "Query GTI threat intelligence knowledge base.",
              lambda query="": {
                  "status": "success",
                  "server": "gti",
                  "query": query,
              },
          ),
          (
              "search_threats",
              "Search GTI for threats, campaigns, or malware families.",
              lambda query="": {
                  "status": "success",
                  "server": "gti",
                  "query": query,
              },
          ),
          (
              "search_threat_actors",
              "Search GTI for threat actor profiles.",
              lambda query="": {
                  "status": "success",
                  "server": "gti",
                  "query": query,
              },
          ),
          (
              "search_vulnerabilities",
              "Search GTI for CVE vulnerability intelligence.",
              lambda query="": {
                  "status": "success",
                  "server": "gti",
                  "query": query,
              },
          ),
      ],
  }

  prefix_map = {"siem": "secops-mcp", "soar": "soar-mcp", "gti": "gti-mcp"}
  prefix = prefix_map.get(server, server)
  tools: list[BaseTool] = []

  for short_name, desc, fn in specs.get(server, []):

    def _make_fn(f, s_name, d):
      def _wrapped(**kwargs):
        return f(**kwargs)

      _wrapped.__name__ = s_name
      _wrapped.__doc__ = d
      _wrapped.__signature__ = inspect.signature(f)  # type: ignore[attr-defined]
      return _wrapped

    fn_obj = _make_fn(fn, short_name, desc)
    ft = FunctionTool(func=fn_obj)
    tools.append(ft)

    prefixed_name = f"{prefix}_{short_name}"
    schema = _extract_schema_from_callable(fn)
    registry.register_tool(
        MCPToolMetadata(
            name=prefixed_name,
            server=server,
            description=desc,
            input_schema=schema,
            executor=fn_obj,
        )
    )
    registry.register_tool(
        MCPToolMetadata(
            name=short_name,
            server=server,
            description=desc,
            input_schema=schema,
            executor=fn_obj,
        )
    )

  return tools
