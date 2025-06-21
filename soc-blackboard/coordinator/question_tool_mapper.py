"""
Investigation Question Tool Mapper

Maps investigation questions to available tools and identifies missing capabilities.
This runs AFTER question generation to avoid tool availability influencing question quality.
"""

import json
from typing import Dict, List, Any
from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types


class QuestionToolMapper:
    """
    Maps investigation questions to available MCP tools and identifies capability gaps.
    
    This runs as a separate phase AFTER question generation to ensure that tool
    availability doesn't influence the comprehensiveness of questions asked.
    """
    
    def __init__(self, tools):
        self.tools = tools
        self.available_mcp_tools = self._catalog_available_tools()
        
    def _catalog_available_tools(self) -> Dict[str, List[str]]:
        """Catalog available MCP tools by category."""
        # This would be enhanced to dynamically discover available tools
        # For now, using known tool categories from the coordinator instructions
        return {
            "siem_tools": [
                "search_security_events", "get_security_alerts", "lookup_entity",
                "list_security_rules", "get_ioc_matches", "search_logs",
                "get_asset_info", "query_timeline", "search_indicators",
                "get_detection_results", "list_cases"
            ],
            "soar_tools": [
                "list_cases", "post_case_comment", "list_alerts_by_case",
                "change_case_priority", "get_case_full_details", "create_case",
                "update_case_status", "add_case_artifact", "get_case_artifacts",
                "close_case", "assign_case", "escalate_case"
            ],
            "gti_tools": [
                "get_collection_report", "search_threats", "get_domain_report",
                "get_file_report", "get_ip_address_report", "get_url_report",
                "search_malware", "get_threat_actor_info", "get_campaign_info",
                "search_vulnerabilities", "get_sandbox_report"
            ],
            "utility_tools": [
                "write_report", "get_current_time", "blackboard_read",
                "blackboard_write", "blackboard_query"
            ]
        }
    
    async def map_tools_to_questions(self, questions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Map available tools and identify missing tools for each question.
        
        Args:
            questions: List of investigation questions
            
        Returns:
            Enhanced questions with tool mappings and wishlists
        """
        
        enhanced_questions = []
        
        for question in questions:
            enhanced_question = question.copy()
            
            # Generate tool mapping for this question
            tool_mapping = await self._generate_tool_mapping_for_question(question)
            
            enhanced_question.update({
                "available_tools": tool_mapping["available_tools"],
                "suggested_approach": tool_mapping["suggested_approach"],
                "tool_wishlist": tool_mapping["tool_wishlist"],
                "data_sources_needed": tool_mapping["data_sources_needed"],
                "alternative_methods": tool_mapping["alternative_methods"]
            })
            
            enhanced_questions.append(enhanced_question)
        
        return enhanced_questions
    
    async def _generate_tool_mapping_for_question(self, question: Dict[str, Any]) -> Dict[str, Any]:
        """Generate tool mapping for a single question using AI analysis."""
        
        # Create specialized tool mapping agent
        mapping_agent = Agent(
            name="tool_mapper",
            model="gemini-2.5-pro-preview-05-06",
            description="Investigation tool mapping specialist",
            instruction=self._get_tool_mapping_instructions(),
            tools=self.tools
        )
        
        # Build prompt for tool mapping
        prompt = self._build_tool_mapping_prompt(question)
        
        # Run tool mapping
        runner = Runner(
            app_name='tool_mapper',
            agent=mapping_agent,
            session_service=InMemorySessionService(),
        )
        
        session = await runner.session_service.create_session(
            app_name='tool_mapper',
            user_id='system'
        )
        
        content = types.Content(role='user', parts=[types.Part(text=prompt)])
        
        # Generate tool mapping
        mapping_response = None
        async for event in runner.run_async(
            session_id=session.id,
            user_id=session.user_id,
            new_message=content
        ):
            if hasattr(event, 'response') and event.response:
                mapping_response = event.response
            elif hasattr(event, 'content') and event.content:
                mapping_response = event.content
        
        # Parse and return mapping
        if mapping_response:
            return self._parse_tool_mapping_response(mapping_response)
        else:
            return self._get_default_tool_mapping(question)
    
    def _get_tool_mapping_instructions(self) -> str:
        """Get instructions for the tool mapping agent."""
        return """
You are a cybersecurity tool mapping specialist. Your job is to analyze investigation questions and map them to available tools and data sources.

## Your Mission
For each investigation question provided, identify:
1. Available MCP tools that can help answer the question
2. Suggested investigation approach using those tools
3. Tools/data we wish we had but don't currently have
4. Alternative methods if preferred tools aren't available

## Available MCP Tool Categories

### SIEM Tools (Chronicle)
- search_security_events: Search for security events
- get_security_alerts: Retrieve security alerts  
- lookup_entity: Look up entity information
- list_security_rules: List detection rules
- get_ioc_matches: Get IOC matches
- search_logs: Search log data
- get_asset_info: Get asset information
- query_timeline: Query event timelines
- search_indicators: Search for indicators
- get_detection_results: Get detection results

### SOAR Tools (Security Orchestration)
- list_cases: List security cases
- get_case_full_details: Get complete case information
- post_case_comment: Add comments to cases
- list_alerts_by_case: Get alerts for a case
- change_case_priority: Update case priority
- create_case: Create new cases
- update_case_status: Update case status
- add_case_artifact: Add artifacts to cases
- get_case_artifacts: Get case artifacts

### GTI Tools (Google Threat Intelligence/VirusTotal)
- get_collection_report: Get threat intelligence reports
- search_threats: Search for threats
- get_domain_report: Analyze domains
- get_file_report: Analyze files
- get_ip_address_report: Analyze IP addresses
- get_url_report: Analyze URLs
- search_malware: Search malware databases
- get_threat_actor_info: Get threat actor information
- get_campaign_info: Get campaign information
- search_vulnerabilities: Search vulnerability databases

### Utility Tools
- write_report: Write investigation reports
- get_current_time: Get current timestamp
- blackboard_read: Read from investigation blackboard
- blackboard_write: Write to investigation blackboard
- blackboard_query: Query blackboard data

## Output Format
Provide your analysis in JSON format:

```json
{
  "available_tools": [
    {
      "tool_name": "specific_tool_name",
      "tool_category": "siem|soar|gti|utility",
      "relevance": "high|medium|low",
      "usage_description": "How this tool helps answer the question"
    }
  ],
  "suggested_approach": "Step-by-step approach using available tools",
  "tool_wishlist": [
    {
      "tool_name": "desired_tool_name",
      "description": "What this tool would do",
      "why_needed": "Why this would be valuable",
      "priority": "high|medium|low"
    }
  ],
  "data_sources_needed": [
    "Type of data or logs needed"
  ],
  "alternative_methods": [
    "Alternative approaches if preferred tools unavailable"
  ]
}
```

## Guidelines
- Be specific about which tools are most relevant
- Suggest realistic investigation workflows
- Identify genuine capability gaps
- Consider both technical and practical constraints
- Think about data correlation across tools
- Consider automation opportunities
"""
    
    def _build_tool_mapping_prompt(self, question: Dict[str, Any]) -> str:
        """Build the prompt for tool mapping."""
        
        available_tools_summary = {}
        for category, tools in self.available_mcp_tools.items():
            available_tools_summary[category] = len(tools)
        
        prompt = f"""
Analyze this investigation question and map it to available tools and identify missing capabilities.

## Investigation Question:
**ID**: {question.get('id', 'unknown')}
**Category**: {question.get('category', 'general')}
**Priority**: {question.get('priority', 'medium')}
**Question**: {question.get('question', 'No question provided')}
**Rationale**: {question.get('rationale', 'No rationale provided')}
**Expected Evidence**: {question.get('expected_evidence_types', [])}

## Available Tools Summary:
{json.dumps(available_tools_summary, indent=2)}

## Task:
Map this question to specific available MCP tools and identify what tools/data we wish we had.

Consider:
1. Which specific MCP tools can directly help answer this question?
2. What would be the step-by-step investigation approach?
3. What tools or data sources are missing that would make this easier?
4. What alternative approaches exist if preferred tools aren't available?
5. How would you correlate data across multiple tools?

Focus on practical, actionable tool usage that directly addresses the question.

Provide your response in the specified JSON format.
"""
        return prompt
    
    def _parse_tool_mapping_response(self, response: str) -> Dict[str, Any]:
        """Parse the AI response into structured tool mapping."""
        try:
            # Try to extract JSON from the response
            if "```json" in response:
                json_start = response.find("```json") + 7
                json_end = response.find("```", json_start)
                json_content = response[json_start:json_end].strip()
            elif "{" in response and "}" in response:
                json_start = response.find("{")
                json_end = response.rfind("}") + 1
                json_content = response[json_start:json_end]
            else:
                raise ValueError("No JSON found in response")
            
            parsed = json.loads(json_content)
            return parsed
            
        except Exception as e:
            print(f"Failed to parse tool mapping response: {e}")
            return self._get_default_tool_mapping({})
    
    def _get_default_tool_mapping(self, question: Dict[str, Any]) -> Dict[str, Any]:
        """Generate default tool mapping if AI generation fails."""
        
        category = question.get("category", "general")
        question_text = question.get("question", "").lower()
        
        # Simple heuristic mapping based on question content
        available_tools = []
        tool_wishlist = []
        data_sources_needed = []
        
        # Network-related questions
        if any(term in question_text for term in ["network", "ip", "connection", "traffic", "dns"]):
            available_tools.extend([
                {
                    "tool_name": "search_security_events",
                    "tool_category": "siem",
                    "relevance": "high",
                    "usage_description": "Search for network-related security events"
                },
                {
                    "tool_name": "get_ip_address_report",
                    "tool_category": "gti",
                    "relevance": "high", 
                    "usage_description": "Analyze IP addresses for reputation and threat intelligence"
                }
            ])
            data_sources_needed.extend(["network_logs", "dns_logs", "firewall_logs"])
        
        # Malware/file-related questions
        if any(term in question_text for term in ["malware", "file", "hash", "executable", "process"]):
            available_tools.extend([
                {
                    "tool_name": "get_file_report",
                    "tool_category": "gti",
                    "relevance": "high",
                    "usage_description": "Analyze file hashes for malware detection"
                },
                {
                    "tool_name": "search_malware",
                    "tool_category": "gti", 
                    "relevance": "medium",
                    "usage_description": "Search malware databases for related samples"
                }
            ])
            data_sources_needed.extend(["endpoint_logs", "process_logs", "file_hashes"])
        
        # Authentication/user-related questions
        if any(term in question_text for term in ["user", "account", "login", "authentication", "credential"]):
            available_tools.extend([
                {
                    "tool_name": "search_security_events",
                    "tool_category": "siem",
                    "relevance": "high",
                    "usage_description": "Search for authentication-related events"
                }
            ])
            data_sources_needed.extend(["authentication_logs", "active_directory_logs"])
        
        return {
            "available_tools": available_tools,
            "suggested_approach": f"Use available tools to investigate {category} aspects of the question",
            "tool_wishlist": tool_wishlist,
            "data_sources_needed": data_sources_needed,
            "alternative_methods": ["Manual log analysis", "Correlation with other findings"]
        }