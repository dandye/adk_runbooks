import logging
from pathlib import Path

from google.adk.agents import Agent

from .sub_agents.soc_analyst_tier1 import agent as soc_analyst_tier1_agent_module
from .sub_agents.soc_analyst_tier2 import agent as soc_analyst_tier2_agent_module
from .sub_agents.cti_researcher import agent as cti_researcher_agent_module
from .sub_agents.threat_hunter import agent as threat_hunter_agent_module
from .sub_agents.soc_analyst_tier3 import agent as soc_analyst_tier3_agent_module
from .sub_agents.incident_responder import agent as incident_responder_agent_module
from .sub_agents.detection_engineer import agent as detection_engineer_agent_module

from .tools.tools import get_current_time, write_report, get_agent_tools, load_persona_and_runbooks

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

# Load persona and runbooks for the manager
BASE_DIR = Path(__file__).resolve().parent
persona_file_path = (BASE_DIR / "../../../adk_runbooks/rules-bank/personas/soc_manager.md").resolve()
runbook_files = [
    # Guidelines
    (BASE_DIR / "../../../adk_runbooks/rules-bank/run_books/guidelines/report_writing.md").resolve(),
    # IRPs
    (BASE_DIR / "../../../adk_runbooks/rules-bank/run_books/irps/compromised_user_account_response.md").resolve(),
    (BASE_DIR / "../../../adk_runbooks/rules-bank/run_books/irps/phishing_response.md").resolve(),
    (BASE_DIR / "../../../adk_runbooks/rules-bank/run_books/irps/ransomware_response.md").resolve(),
    # Runbooks
    (BASE_DIR / "../../../adk_runbooks/rules-bank/run_books/triage_alerts.md").resolve(),
    (BASE_DIR / "../../../adk_runbooks/rules-bank/run_books/prioritize_and_investigate_a_case.md").resolve(),
    (BASE_DIR / "../../../adk_runbooks/rules-bank/run_books/close_duplicate_or_similar_cases.md").resolve(),
    (BASE_DIR / "../../../adk_runbooks/rules-bank/run_books/basic_ioc_enrichment.md").resolve(),
    (BASE_DIR / "../../../adk_runbooks/rules-bank/run_books/suspicious_login_triage.md").resolve(),
    (BASE_DIR / "../../../adk_runbooks/rules-bank/run_books/investgate_a_case_w_external_tools.md").resolve(),
    (BASE_DIR / "../../../adk_runbooks/rules-bank/run_books/ioc_containment.md").resolve(),
    (BASE_DIR / "../../../adk_runbooks/rules-bank/run_books/basic_endpoint_triage_isolation.md").resolve(),
    (BASE_DIR / "../../../adk_runbooks/rules-bank/run_books/deep_dive_ioc_analysis.md").resolve(),
    (BASE_DIR / "../../../adk_runbooks/rules-bank/run_books/malware_triage.md").resolve(),
    (BASE_DIR / "../../../adk_runbooks/rules-bank/run_books/guided_ttp_hunt_credential_access.md").resolve(),
    (BASE_DIR / "../../../adk_runbooks/rules-bank/run_books/lateral_movement_hunt_psexec_wmi.md").resolve(),
    (BASE_DIR / "../../../adk_runbooks/rules-bank/run_books/advanced_threat_hunting.md").resolve(),
    (BASE_DIR / "../../../adk_runbooks/rules-bank/run_books/detection_rule_validation_tuning.md").resolve(),
    (BASE_DIR / "../../../adk_runbooks/rules-bank/run_books/create_an_investigation_report.md").resolve(),
]

persona_description = load_persona_and_runbooks(
    persona_file_path,
    runbook_files,
    default_persona_description="SOC Manager: Responsible for delegating to other agents and writing reports."
)

# Create the root agent directly
root_agent = Agent(
    name="manager",
    #model="gemini-2.5-flash",
    model="gemini-2.5-pro",
    description=persona_description,
    instruction="""
    You are the SOC Manager agent, responsible for overseeing and orchestrating the work of specialized sub-agents. Your primary goal is to ensure efficient and effective incident response and SOC operations.

    **Incident Response Plan (IRP) Execution:**
    When an IRP is invoked (e.g., "Start Malware IRP for CASE_ID 123"):
    1.  Your **first priority** is to understand the active IRP. The IRP details, including phases, steps, and responsible personas, are part of your contextual description.
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

    **Your Tools:**
    You have direct access to these tools for oversight and reporting:
    - get_current_time
    - write_report

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
    ],
    tools=[
        get_current_time,
        write_report,
    ],
)