"""Script to enrich all SKILL.md packages with unified Skills + OKF frontmatter
and metadata.adk_additional_tools for native ADK SkillToolset dynamic binding.
"""

import re
from pathlib import Path

import yaml

base_dir = Path(__file__).resolve().parent.parent.parent
skills_dir = base_dir / "skills"
rules_bank_dir = base_dir / "rules-bank" / "run_books"

# Map of skill names to their corresponding ADK Graph Workflow tool names
SKILL_TO_WORKFLOW_TOOLS: dict[str, list[str]] = {
    "advanced-threat-hunting": [
        "run_advanced_threat_hunting_workflow",
        "run_metaanalysis_workflow",
    ],
    "alert-report": ["run_alert_report_workflow"],
    "apt-threat-hunt": ["run_apt_threat_hunt_workflow"],
    "basic-endpoint-triage-isolation": ["run_endpoint_triage_workflow"],
    "basic-ioc-enrichment": ["run_basic_ioc_enrichment_workflow"],
    "case-event-timeline-analysis": ["run_timeline_process_analysis_workflow"],
    "case-report": ["run_case_report_workflow"],
    "close-duplicate-cases": ["run_close_duplicate_cases_workflow"],
    "cloud-vulnerability-triage": ["run_cloud_vulnerability_triage_workflow"],
    "compare-gti-collection": ["run_compare_gti_collection_workflow"],
    "compromised-user-account-response": ["run_compromised_user_irp_workflow"],
    "create-investigation-report": ["run_create_investigation_report_workflow"],
    "deep-dive-ioc-analysis": ["run_deep_dive_ioc_analysis_workflow"],
    "detection-as-code-rule-tuning": ["run_detection_as_code_tuning_workflow"],
    "detection-as-code-workflows": ["run_detection_as_code_tuning_workflow"],
    "detection-report": ["run_detection_report_workflow"],
    "detection-rule-validation-tuning": [
        "run_detection_rule_validation_workflow"
    ],
    "group-cases": ["run_group_cases_workflow"],
    "group-cases-v2": ["run_group_cases_v2_workflow"],
    "guided-ttp-hunt-credential-access": [
        "run_credential_access_hunt_workflow"
    ],
    "investigate-case-external-tools": [
        "run_investigate_case_external_tools_workflow"
    ],
    "investigate-gti-collection": ["run_investigate_gti_collection_workflow"],
    "ioc-containment": ["run_ioc_containment_workflow"],
    "ioc-threat-hunt": ["run_ioc_threat_hunt_workflow"],
    "lateral-movement-hunt-psexec-wmi": ["run_lateral_movement_hunt_workflow"],
    "malware-incident-response": ["run_malware_irp_workflow"],
    "malware-triage": ["run_malware_triage_workflow"],
    "phishing-response": ["run_phishing_irp_workflow"],
    "prioritize-and-investigate-case": [
        "run_prioritize_investigate_case_workflow"
    ],
    "proactive-hunt-gti-campaign": ["run_proactive_gti_threat_hunt_workflow"],
    "ransomware-response": ["run_ransomware_irp_workflow"],
    "report-writing-guidelines": [
        "run_post_incident_review_workflow",
        "run_ueba_report_workflow",
    ],
    "suspicious-login-triage": [
        "run_suspicious_login_workflow",
        "run_suspicious_login_triage_workflow",
    ],
    "triage-alerts": ["run_triage_alerts_workflow", "run_demo_soc_t2_workflow"],
}

# Map of atomic/common skill names to their primary MCP tools
ATOMIC_SKILL_MCP_TOOLS: dict[str, list[str]] = {
    "domain-get-gti-report": ["gti-mcp_get_domain_report"],
    "domain-get-secops-threat-intel": ["secops-mcp_get_threat_intel"],
    "domain-lookup-entity-chronicle": ["secops-mcp_lookup_entity"],
    "domain-search-dns-chronicle": ["secops-mcp_search_security_events"],
    "domain-search-network-traffic-chronicle": [
        "secops-mcp_search_security_events"
    ],
    "hash-get-gti-report": ["gti-mcp_get_file_report"],
    "hash-get-secops-threat-intel": ["secops-mcp_get_threat_intel"],
    "hash-lookup-entity-chronicle": ["secops-mcp_lookup_entity"],
    "hash-search-process-events-chronicle": [
        "secops-mcp_search_security_events"
    ],
    "ip-get-gti-report": ["gti-mcp_get_ip_address_report"],
    "ip-get-secops-threat-intel": ["secops-mcp_get_threat_intel"],
    "ip-lookup-entity-chronicle": ["secops-mcp_lookup_entity"],
    "ip-search-network-traffic-chronicle": [
        "secops-mcp_search_security_events",
        "secops-mcp_lookup_entity",
    ],
    "url-get-gti-report": ["gti-mcp_get_url_report"],
    "url-get-secops-threat-intel": ["secops-mcp_get_threat_intel"],
    "url-search-chronicle": ["secops-mcp_search_security_events"],
    "user-lookup-entity-chronicle": ["secops-mcp_lookup_entity"],
    "user-search-login-activity-chronicle": [
        "secops-mcp_search_security_events"
    ],
    "user-search-process-activity-chronicle": [
        "secops-mcp_search_security_events"
    ],
}

# Map of legacy runbook frontmatter metadata by name
legacy_meta = {}
if rules_bank_dir.exists():
  for p in rules_bank_dir.rglob("*.md"):
    try:
      content = p.read_text(encoding="utf-8")
      m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", content, re.DOTALL)
      if m:
        data = yaml.safe_load(m.group(1))
        if isinstance(data, dict):
          norm_key = p.stem.lower().replace("_", "-")
          legacy_meta[norm_key] = data
    except Exception:
      pass


def extract_additional_tools(skill_name: str, body: str) -> list[str]:
  """Derive adk_additional_tools from workflow mappings and MCP tool references in body."""
  tools: list[str] = []
  seen: set[str] = set()

  def _add(t: str):
    if t and not t.endswith("_") and t not in seen:
      seen.add(t)
      tools.append(t)

  for wf_tool in SKILL_TO_WORKFLOW_TOOLS.get(skill_name, []):
    _add(wf_tool)

  for atomic_tool in ATOMIC_SKILL_MCP_TOOLS.get(skill_name, []):
    _add(atomic_tool)

  mcp_matches = re.findall(
      r"(?:secops-mcp|soar-mcp|gti-mcp|secops_mcp|soar_mcp|gti_mcp)[_-][a-zA-Z0-9_]+",
      body,
  )
  for m_tool in sorted(set(mcp_matches)):
    # Normalize prefix to <server>-mcp_<tool>
    norm_tool = re.sub(r"^(secops|soar|gti)[_-]mcp[_-]", r"\1-mcp_", m_tool)
    if not norm_tool.endswith("_"):
      _add(norm_tool)

  return tools


def update_skills():
  count = 0
  for skill_file in sorted(skills_dir.rglob("SKILL.md")):
    content = skill_file.read_text(encoding="utf-8")
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", content, re.DOTALL)
    if not m:
      continue

    raw_yaml = m.group(1)
    body = m.group(2)

    data = yaml.safe_load(raw_yaml)
    if not isinstance(data, dict):
      continue

    skill_name = data.get("name", skill_file.parent.name)
    norm_name = skill_name.lower().replace("_", "-")

    # Derive title
    first_h1_match = re.search(r"^#\s+(.+)$", body, re.MULTILINE)
    if first_h1_match:
      raw_title = first_h1_match.group(1).strip()
      if raw_title.startswith("Runbook:"):
        title = "Skill:" + raw_title[len("Runbook:") :]
      elif not raw_title.startswith("Skill:"):
        title = f"Skill: {raw_title}"
      else:
        title = raw_title
    elif norm_name in legacy_meta and "title" in legacy_meta[norm_name]:
      leg_title = legacy_meta[norm_name]["title"]
      if leg_title.startswith("Runbook:"):
        title = "Skill:" + leg_title[len("Runbook:") :]
      elif not leg_title.startswith("Skill:"):
        title = f"Skill: {leg_title}"
      else:
        title = leg_title
    else:
      title = f"Skill: {skill_name.replace('-', ' ').title()}"

    # Determine timestamp
    if norm_name in legacy_meta and isinstance(
        legacy_meta[norm_name].get("generated"), dict
    ):
      gen_info = legacy_meta[norm_name]["generated"]
    elif isinstance(data.get("generated"), dict):
      gen_info = data["generated"]
    else:
      gen_info = {
          "by": "process:google-labs-jules",
          "at": "2026-08-20T02:00:00Z",
      }

    additional_tools = extract_additional_tools(skill_name, body)

    new_frontmatter = {
        "name": skill_name,
        "description": data.get("description", ""),
        "category": data.get("category", skill_file.parent.parent.name),
        "version": data.get("version", "1.0.0"),
        "type": "Skill",
        "title": title,
        "generated": gen_info,
    }
    if additional_tools:
      new_frontmatter["metadata"] = {
          "adk_additional_tools": additional_tools,
      }

    yaml_str = yaml.dump(
        new_frontmatter, sort_keys=False, default_flow_style=False
    ).strip()
    new_file_content = f"---\n{yaml_str}\n---\n\n{body.lstrip()}"

    skill_file.write_text(new_file_content, encoding="utf-8")
    count += 1
    print(
        f"[*] Updated {skill_file.relative_to(base_dir)} (Tools: {len(additional_tools)})"
    )

  print(
      f"\n[+] Successfully updated {count} SKILL.md packages with unified Skills + OKF frontmatter."
  )


if __name__ == "__main__":
  update_skills()
