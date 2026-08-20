import pytest
from pathlib import Path
from manager.agent import root_agent
from manager.tools.tools import (
    load_skill,
    list_available_skills,
    search_mcp_tools,
    get_mcp_tool_schema,
    execute_mcp_tool,
    get_agent_tools,
)
from manager.sub_agents.soc_analyst_tier1.agent import get_agent as get_soc_analyst_tier1
from manager.sub_agents.soc_analyst_tier2.agent import get_agent as get_soc_analyst_tier2
from manager.sub_agents.soc_analyst_tier3.agent import get_agent as get_soc_analyst_tier3
from manager.sub_agents.cti_researcher.agent import get_agent as get_cti_researcher
from manager.sub_agents.threat_hunter.agent import get_agent as get_threat_hunter
from manager.sub_agents.incident_responder.agent import get_agent as get_incident_responder
from manager.sub_agents.detection_engineer.agent import get_agent as get_detection_engineer
from manager.sub_agents.llm_judge.agent import get_agent as get_llm_judge


def test_manager_agent_initialization():
    assert root_agent is not None
    assert root_agent.name == "manager"
    assert "### Available Skills (Progressive Disclosure)" in root_agent.description
    assert len(root_agent.description) < 12000, f"Manager description too long ({len(root_agent.description)} chars)"

    tool_names = [getattr(t, "__name__", str(t)) for t in root_agent.tools]
    assert any("load_skill" in name for name in tool_names), "load_skill tool missing from manager"
    assert any("list_available_skills" in name for name in tool_names), "list_available_skills tool missing from manager"
    assert any("search_mcp_tools" in name for name in tool_names), "search_mcp_tools tool missing from manager"
    assert any("get_mcp_tool_schema" in name for name in tool_names), "get_mcp_tool_schema tool missing from manager"
    assert any("execute_mcp_tool" in name for name in tool_names), "execute_mcp_tool tool missing from manager"

    # Verify sub-agents are registered on root_agent
    sub_agent_names = [sa.name for sa in root_agent.sub_agents]
    expected_sub_agents = [
        "soc_analyst_tier1",
        "soc_analyst_tier2",
        "soc_analyst_tier3",
        "cti_researcher",
        "threat_hunter",
        "incident_responder",
        "detection_engineer",
        "llm_judge",
    ]
    for expected in expected_sub_agents:
        assert expected in sub_agent_names, f"Expected sub-agent {expected} not in manager sub_agents"


@pytest.mark.parametrize(
    "getter,expected_name,expected_skills",
    [
        (
            get_soc_analyst_tier1,
            "soc_analyst_tier1",
            ["triage-alerts", "basic-ioc-enrichment", "suspicious-login-triage"],
        ),
        (
            get_soc_analyst_tier2,
            "soc_analyst_tier2",
            ["prioritize-and-investigate-case", "deep-dive-ioc-analysis", "case-event-timeline-analysis"],
        ),
        (
            get_soc_analyst_tier3,
            "soc_analyst_tier3",
            ["compromised-user-account-response", "ransomware-response", "detection-rule-validation-tuning"],
        ),
        (
            get_cti_researcher,
            "cti_researcher",
            ["investigate-gti-collection", "proactive-hunt-gti-campaign", "compare-gti-collection"],
        ),
        (
            get_threat_hunter,
            "threat_hunter",
            ["advanced-threat-hunting", "apt-threat-hunt", "guided-ttp-hunt-credential-access"],
        ),
        (
            get_incident_responder,
            "incident_responder",
            ["compromised-user-account-response", "malware-incident-response", "ioc-containment"],
        ),
        (
            get_detection_engineer,
            "detection_engineer",
            ["detection-rule-validation-tuning", "detection-as-code-workflows", "detection-report"],
        ),
        (
            get_llm_judge,
            "llm_judge",
            ["report-writing-guidelines"],
        ),
    ],
)
def test_sub_agents_initialization(getter, expected_name, expected_skills):
    # Mock / shared tools
    tools = get_agent_tools()
    agent = getter(tools)

    assert agent.name == expected_name
    assert "### Available Skills (Progressive Disclosure)" in agent.description
    assert len(agent.description) < 12000, f"Agent {agent.name} description too long ({len(agent.description)} chars)"

    for skill in expected_skills:
        assert skill in agent.description, f"Expected skill {skill} not found in {agent.name} description"

    tool_names = [getattr(t, "__name__", str(t)) for t in agent.tools]
    assert any("load_skill" in name for name in tool_names), f"load_skill tool missing from {agent.name}"
    assert any("list_available_skills" in name for name in tool_names), f"list_available_skills missing from {agent.name}"
    assert any("search_mcp_tools" in name for name in tool_names), f"search_mcp_tools missing from {agent.name}"
    assert any("get_mcp_tool_schema" in name for name in tool_names), f"get_mcp_tool_schema missing from {agent.name}"
    assert any("execute_mcp_tool" in name for name in tool_names), f"execute_mcp_tool missing from {agent.name}"
