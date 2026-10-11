import logging
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from manager/.env and external/mcp-security/.env
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
load_dotenv((BASE_DIR / "../../external/mcp-security/.env").resolve())

from google.adk.agents import Agent

from .sub_agents.soc_analyst_tier1 import agent as soc_analyst_tier1_agent_module
from .sub_agents.soc_analyst_tier2 import agent as soc_analyst_tier2_agent_module
from .sub_agents.cti_researcher import agent as cti_researcher_agent_module
from .sub_agents.threat_hunter import agent as threat_hunter_agent_module
from .sub_agents.soc_analyst_tier3 import agent as soc_analyst_tier3_agent_module
from .sub_agents.incident_responder import agent as incident_responder_agent_module
from .sub_agents.detection_engineer import agent as detection_engineer_agent_module
from .sub_agents.llm_judge import agent as llm_judge_agent_module

from .tools.tools import (
    get_current_time,
    write_report,
    get_agent_tools,
    load_persona_with_skills_catalog,
    read_file_content,
    load_skill,
    list_available_skills,
    search_mcp_tools,
    get_mcp_tool_schema,
    execute_mcp_tool,
    create_google_doc,
    read_google_doc,
    insert_doc_comments,
    propose_doc_suggested_edits,
    review_google_doc_with_stage_a,
    stage_runbook_update_as_google_doc,
    post_reviewed_doc_to_soar_case,
    verify_and_redline_udm_queries_in_doc,
    verify_and_redline_yaral2_rules_in_doc,
    verify_and_redline_mitre_and_cve_in_doc,
    sanitize_and_redline_telemetry_in_doc,
    inspect_doc_suggestions,
    export_accepted_doc_to_markdown,
)

# Set the root logger to output debug messages
logging.basicConfig(level=logging.ERROR)

# Initialize shared tools once
shared_tools = get_agent_tools()

# Initialize all sub-agents with the shared tools
initialized_soc_analyst_tier1 = soc_analyst_tier1_agent_module.get_agent(shared_tools)
initialized_soc_analyst_tier2 = soc_analyst_tier2_agent_module.get_agent(shared_tools)
initialized_cti_researcher = cti_researcher_agent_module.get_agent(shared_tools)
initialized_threat_hunter = threat_hunter_agent_module.get_agent(shared_tools)
initialized_soc_analyst_tier3 = soc_analyst_tier3_agent_module.get_agent(shared_tools)
initialized_incident_responder = incident_responder_agent_module.get_agent(shared_tools)
initialized_detection_engineer = detection_engineer_agent_module.get_agent(shared_tools)
initialized_llm_judge = llm_judge_agent_module.get_agent(shared_tools)

# Load persona and skills catalog for the manager
BASE_DIR = Path(__file__).resolve().parent
persona_file_path = (BASE_DIR / "../../rules-bank/personas/soc_manager.md").resolve()
manager_skills = [
    "compromised-user-account-response",
    "phishing-response",
    "ransomware-response",
    "malware-incident-response",
    "report-writing-guidelines",
    "create-investigation-report",
]

persona_description = load_persona_with_skills_catalog(
    str(persona_file_path),
    skill_names=manager_skills,
    default_persona_description="SOC Manager: Responsible for delegating to other agents and writing reports."
)

# Create the root agent directly
root_agent = Agent(
    name="manager",
    model="gemini-3.7-flash",
    description=persona_description,
    instruction="""
    You are the SOC Manager agent, responsible for overseeing and orchestrating the work of specialized sub-agents. Your primary goal is to ensure efficient and effective incident response and SOC operations.

    When executing a task, check your Available Skills. Call `load_skill(skill_name)` to retrieve detailed procedural guidance and rubrics when relevant.

    **Incident Response Plan (IRP) Execution:**
    When an IRP is invoked (e.g., "Start Malware IRP for CASE_ID 123"):
    1.  Your **first priority** is to understand the active IRP. The IRP details, including phases, steps, and responsible personas, are part of your contextual description or loaded via `load_skill`.
    2.  You **MUST** meticulously follow the IRP. For each step, identify the `**Responsible Persona(s):**` as specified in the IRP.
    3.  Delegate tasks **strictly according to these IRP assignments**. For example, if the IRP says "SOC Analyst T1" is responsible for initial triage, you delegate that to the `soc_analyst_tier1` sub-agent.
    4.  Ensure that control returns to you after a sub-agent completes its delegated IRP task. You will then consult the IRP for the next step and delegate to the next responsible persona.
    5.  Provide clear context and necessary inputs (from the IRP or previous steps) to sub-agents when delegating.
    6.  If the IRP specifies "SOC Manager (Approval)" for a step, you must make an explicit approval decision (or consult the user if in an interactive session) before proceeding.

    **General Delegation:**
    For tasks not covered by a specific IRP step, use your best judgment to delegate to the most appropriate sub-agent based on their described specializations:
    - soc_analyst_tier1: Initial alert triage, basic SIEM queries, and initial data gathering.
    - soc_analyst_tier2: Deeper investigation, SOAR interactions, complex alert analysis, and initial IOC enrichment.
    - cti_researcher: In-depth threat intelligence, malware analysis, actor profiling, and advanced IOC enrichment.
    - threat_hunter: Proactive threat hunting, hypothesis-driven investigations, and advanced data analysis.
    - soc_analyst_tier3: Advanced incident response coordination for complex incidents, deep-dive forensics, and major security event leadership.
    - incident_responder: Hands-on execution of containment, eradication, and recovery phases of an incident as directed by an IRP or yourself.
    - detection_engineer: Designing, developing, testing, and tuning security detection rules and analytics.
    - llm_judge: Evaluating the quality and completeness of runbook executions by other agents.

    **Grounding Policy (VERIFY BEFORE YOU SUGGEST):**
    - For Google Cloud, Chronicle SIEM/SOAR, IAM roles, Vertex AI, Gemini, or ADK claims and commands, verify against the Developer Knowledge MCP tools (`devknowledge_search_documents`, `devknowledge_answer_query`, `devknowledge_get_documents`) first.
    - For external CVEs, third-party vendor advisories (FortiOS, Ivanti, Palo Alto, AWS, Azure), and open-web facts, call the `web_search_verifier` tool.

    **Collaborative Google Docs Runbook & Report Review:**
    When reviewing or proposing improvements to a Google Doc runbook or incident report:
    1. Call `read_google_doc(document_id)` first to read the text and build the UTF-16 index map.
    2. Call `insert_doc_comments(document_id, comments)` **before** proposing edits so comments attach to the pre-edit index spans (include authoritative citation URLs in comments).
    3. Call `propose_doc_suggested_edits(document_id, edits)` **second** to propose non-destructive Suggested Edits (`writeMode="SUGGEST"`).
    4. Or call `review_google_doc_with_stage_a(document_id, semantic_comments, semantic_edits)` to automatically combine Stage A span-based telemetry/secret sanitization, URL defanging, standalone UDM field linting, YARA-L 2.0 (`YL2`) rule linting, and MITRE ATT&CK / CISA KEV CVE span verification with Stage B grounded comments and edits.
    5. Call `sanitize_and_redline_telemetry_in_doc(document_id)` to scan a Google Doc for unredacted offensive telemetry payloads (`-Enc` PowerShell, `FromBase64String`, LOLBin download cradles, credential dumpers, Linux reverse shells) and leaked cloud/API secrets (`ya29.` GCP OAuth2 tokens, `eyJ` JWTs, `AKIA` AWS keys, PEM private keys) by 1-based UTF-16 span and stage `writeMode="SUGGEST"` `<REDACTED_...:sha256=...>` replacements without echoing them through an LLM.
    6. Call `verify_and_redline_udm_queries_in_doc(document_id, run_live_siem_check, diagnose_zero_hit_queries)` to lint Chronicle UDM queries by UTF-16 span, optionally dry-run repaired queries against live Chronicle SIEM (`search_udm`), diagnose 0-hit UDM queries via clause relaxation and live UDM event inspection (`exact_match_on_command_line`, `entity_role_swap`, `value_format_mismatch`), and stage `writeMode="SUGGEST"` corrections.
    7. Call `verify_and_redline_yaral2_rules_in_doc(document_id, run_live_siem_check, diagnose_zero_hit_retrohunt)` to lint single-event and multi-event YARA-L 2.0 (`YL2`) detection rules (distinguishing standard YARA `strings:` from YARA-L 2.0 `events:`, repairing `$var.<field>` UDM paths, cross-event join type mismatches, `match:` placeholder variables, `match:` time windows `over <N><s|m|h|d>`, and single-event/multi-event `condition:` event variables), optionally compile the repaired rule via Chronicle SIEM (`validate_rule`), execute single-event or per-stream multi-event UDM correlation retrohunts via `search_udm`, diagnose 0-hit retrohunt predicates and cross-event join entity-role swaps (`exact_match_on_command_line`, `entity_role_swap`, `value_format_mismatch`, `cross_event_join_entity_role_swap`), and stage compiler-verified `writeMode="SUGGEST"` fixes.
    8. Call `verify_and_redline_mitre_and_cve_in_doc(document_id, run_web_grounding_check)` to verify MITRE ATT&CK technique/sub-technique IDs (`Txxxx` / `Txxxx.xxx`) and CISA KEV CVE identifiers (`CVE-YYYY-NNNN+`) by exact 1-based UTF-16 span, and stage `writeMode="SUGGEST"` corrections with `attack.mitre.org`, `nvd.nist.gov`, and `cisa.gov` citations.
    9. Call `stage_runbook_update_as_google_doc(skill_name, case_id, semantic_comments, semantic_edits, lessons_learned_markdown)` to draft and red-line a Drive runbook from SOAR case lessons learned, and `post_reviewed_doc_to_soar_case` to post the reviewed Google Doc links back to the SOAR case timeline.
    10. Call `inspect_doc_suggestions(document_id, accept_suggestion_ids)` to inspect pending `suggest.*` changes and unified diffs, and `export_accepted_doc_to_markdown(document_id, skill_name, accept_suggestion_ids, output_path, publish_to_drive)` to export accepted red-lines back into a valid Markdown runbook with YAML frontmatter restored.

    **Your Tools:**
    You have direct access to these tools for oversight, skill retrieval, tool discovery, grounding, and reporting:
    - load_skill
    - list_available_skills
    - get_current_time
    - write_report
    - create_google_doc
    - read_google_doc
    - insert_doc_comments
    - propose_doc_suggested_edits
    - review_google_doc_with_stage_a
    - sanitize_and_redline_telemetry_in_doc
    - verify_and_redline_udm_queries_in_doc
    - verify_and_redline_yaral2_rules_in_doc
    - verify_and_redline_mitre_and_cve_in_doc
    - inspect_doc_suggestions
    - export_accepted_doc_to_markdown
    - stage_runbook_update_as_google_doc
    - post_reviewed_doc_to_soar_case
    - web_search_verifier
    - read_file_content
    - search_mcp_tools
    - get_mcp_tool_schema
    - execute_mcp_tool

    Always aim for clear, coordinated, and efficient execution of security operations, leveraging your sub-agents effectively according to their roles and the active IRP.
    """,
    sub_agents=[
        initialized_soc_analyst_tier1,
        initialized_soc_analyst_tier2,
        initialized_cti_researcher,
        initialized_threat_hunter,
        initialized_soc_analyst_tier3,
        initialized_incident_responder,
        initialized_detection_engineer,
        initialized_llm_judge,
    ],
    tools=list(shared_tools),
)
