"""
Investigation Question Generator

Generates comprehensive investigation questions based on SOAR case context.
Helps make tacit SOC analyst knowledge explicit and ensures thorough investigations.
"""

import json
from typing import Dict, List, Any

from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types


class InvestigationQuestionGenerator:
    """
    Generates structured investigation questions based on SOAR case details.
    
    Uses an expert system approach to make tacit SOC analyst knowledge explicit
    by generating comprehensive questions that should be answered during investigation.
    """
    
    def __init__(self, tools):
        self.tools = tools
        
    async def generate_investigation_questions(self, case_details: Dict[str, Any], 
                                             investigation_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate comprehensive investigation questions for a SOAR case.
        
        Args:
            case_details: Complete SOAR case information
            investigation_context: Investigation parameters and context
            
        Returns:
            List of structured questions with categories and priorities
        """
        
        try:
            # Create specialized question generation agent
            question_agent = Agent(
                name="question_generator",
                model="gemini-2.5-pro-preview-05-06",
                description="Investigation question generation specialist",
                instruction=self._get_question_generation_instructions(),
                tools=self.tools
            )
            
            # Build prompt for question generation
            prompt = self._build_question_prompt(case_details, investigation_context)
            
            # Run question generation
            runner = Runner(
                app_name='question_generator',
                agent=question_agent,
                session_service=InMemorySessionService(),
            )
            
            session = await runner.session_service.create_session(
                app_name='question_generator',
                user_id='system'
            )
            
            content = types.Content(role='user', parts=[types.Part(text=prompt)])
            
            # Generate questions
            questions_response = None
            response_text = ""
            async for event in runner.run_async(
                session_id=session.id,
                user_id=session.user_id,
                new_message=content
            ):
                if hasattr(event, 'response') and event.response:
                    questions_response = event.response
                    # Handle different response types
                    if hasattr(event.response, 'candidates') and event.response.candidates:
                        # This is a GenerateContentResponse
                        for candidate in event.response.candidates:
                            if hasattr(candidate, 'content') and hasattr(candidate.content, 'parts'):
                                for part in candidate.content.parts:
                                    if hasattr(part, 'text'):
                                        response_text += part.text
                    elif hasattr(event.response, 'text'):
                        response_text = event.response.text
                    elif isinstance(event.response, str):
                        response_text = event.response
                elif hasattr(event, 'content') and event.content:
                    questions_response = event.content
                    if isinstance(event.content, str):
                        response_text = event.content
            
            # Parse and structure the questions
            if response_text:
                # print(f"DEBUG: Got response text of length {len(response_text)}")
                # print(f"DEBUG: Response preview: {response_text[:200]}...")
                questions = self._parse_questions_response(response_text)
                return questions
            elif questions_response:
                # Try to convert the response object to string
                # print(f"DEBUG: Got response object of type: {type(questions_response)}")
                try:
                    # Handle Content object from genai
                    if hasattr(questions_response, 'parts'):
                        response_str = ""
                        for part in questions_response.parts:
                            if hasattr(part, 'text'):
                                response_str += part.text
                    elif hasattr(questions_response, 'text'):
                        response_str = questions_response.text
                    else:
                        response_str = str(questions_response)
                    
                    if response_str:
                        # print(f"DEBUG: Extracted response text of length {len(response_str)}")
                        questions = self._parse_questions_response(response_str)
                        return questions
                    else:
                        print("DEBUG: No text content found in response object")
                        return self._get_default_questions(case_details, investigation_context)
                except Exception as e:
                    print(f"DEBUG: Failed to parse response object: {e}")
                    import traceback
                    traceback.print_exc()
                    return self._get_default_questions(case_details, investigation_context)
            else:
                print("DEBUG: No response received, using default questions")
                return self._get_default_questions(case_details, investigation_context)
                
        except Exception as e:
            print(f"ERROR: AI question generation failed: {e}")
            return self._get_default_questions(case_details, investigation_context)
    
    def _get_question_generation_instructions(self) -> str:
        """Get instructions for the question generation agent."""
        return """
You are an expert SOC analyst trainer who helps make tacit knowledge explicit by generating comprehensive investigation questions.

## Your Mission
Generate specific, actionable questions that a SOC analyst should answer when investigating a security incident. These questions will guide a systematic investigation and ensure no critical aspects are overlooked.

## Question Generation Principles
1. **Specificity**: Questions should be specific to the case details provided
2. **Actionability**: Each question should lead to concrete investigative actions
3. **Comprehensiveness**: Cover all major investigation areas
4. **Prioritization**: Indicate which questions are most critical
5. **Evidence-focused**: Questions should seek specific evidence and indicators

## Question Categories
Generate questions in these categories:

### Initial Assessment
- What triggered this alert/case?
- What is the scope and severity?
- What systems/users are involved?
- When did the activity occur?

### Technical Analysis
- What specific indicators of compromise are present?
- What attack vectors were used?
- What evidence of persistence exists?
- What lateral movement occurred?
- What data was accessed or exfiltrated?

### Impact Assessment
- Which systems are confirmed compromised?
- What sensitive data was potentially exposed?
- What business processes are affected?
- What is the potential regulatory impact?

### Attribution and Context
- Does this match known threat actor TTPs?
- Is this part of a larger campaign?
- What external threat intelligence is relevant?
- Are there related incidents?

### Response and Containment
- What immediate containment actions are needed?
- What evidence needs preservation?
- What notifications are required?
- What recovery steps are necessary?

## Output Format
Provide questions in JSON format with this structure:
```json
{
  "investigation_questions": [
    {
      "id": "Q001",
      "category": "initial_assessment|technical_analysis|impact_assessment|attribution|response",
      "priority": "critical|high|medium|low",
      "question": "Specific question text here?",
      "rationale": "Why this question is important",
      "investigation_areas": ["network_analysis", "endpoint_investigation", "etc"],
      "expected_evidence_types": ["logs", "network_traffic", "file_hashes", "etc"]
    }
  ]
}
```

## Important Guidelines
- Generate 15-25 questions total
- Make questions specific to the provided case details
- Focus on actionable investigation steps
- Prioritize questions that could reveal critical evidence
- Consider the attack timeline and kill chain phases
- Include questions about both technical and business impact

Generate only questions - do not provide answers or analysis.
"""
    
    def _build_question_prompt(self, case_details: Dict[str, Any], 
                              investigation_context: Dict[str, Any]) -> str:
        """Build the prompt for question generation."""
        
        prompt = f"""
You are preparing an expert system and need to interview a SOC analyst about how they make decisions on a security alert. You want to make tacit knowledge explicit by generating comprehensive investigation questions.

## SOAR Case Details:
{json.dumps(case_details, indent=2)}

## Investigation Context:
{json.dumps(investigation_context, indent=2)}

## Task:
Generate comprehensive, specific investigation questions for this case. Focus on:

1. **Case-Specific Questions**: Tailor questions to the specific indicators, alerts, and context provided
2. **Investigation Methodology**: What systematic steps should be taken?
3. **Evidence Collection**: What specific evidence should be sought?
4. **Risk Assessment**: How should impact and scope be determined?
5. **Response Planning**: What containment and remediation questions need answers?

Consider the following when generating questions:
- The specific alert type and detection method
- The systems and users mentioned in the case
- The timeframe of the incident
- The organization's environment and assets
- Potential attack vectors based on the indicators
- Compliance and regulatory requirements
- Business impact considerations

Generate questions that will guide investigators to:
- Understand the full scope of the incident
- Collect comprehensive evidence
- Assess business and technical impact
- Plan appropriate response actions
- Prevent similar incidents

Provide your response in the specified JSON format with 15-25 detailed, actionable questions.
"""
        return prompt
    
    def _parse_questions_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse the AI response into structured questions."""
        try:
            # Debug: show what we're trying to parse
            # print(f"DEBUG: Attempting to parse response of length {len(response)}")
            
            # Try to extract JSON from the response
            if "```json" in response:
                json_start = response.find("```json") + 7
                json_end = response.find("```", json_start)
                json_content = response[json_start:json_end].strip()
                # print(f"DEBUG: Found JSON block, extracted {len(json_content)} characters")
            elif "{" in response and "}" in response:
                json_start = response.find("{")
                json_end = response.rfind("}") + 1
                json_content = response[json_start:json_end].strip()  # Added strip() here too
                # print(f"DEBUG: Found JSON object, extracted {len(json_content)} characters")
            else:
                # Try to find investigation_questions array directly
                if '"investigation_questions"' in response:
                    print("DEBUG: Found investigation_questions key but couldn't extract JSON structure")
                print(f"DEBUG: Response preview: {response[:500]}...")
                raise ValueError("No JSON found in response")
            
            parsed = json.loads(json_content)
            questions = parsed.get("investigation_questions", [])
            # print(f"DEBUG: Successfully parsed {len(questions)} questions")
            return questions
            
        except json.JSONDecodeError as e:
            print(f"ERROR: JSON parsing failed: {e}")
            print(f"DEBUG: JSON content that failed to parse: {json_content[:200] if 'json_content' in locals() else 'N/A'}...")
            return []
        except Exception as e:
            print(f"ERROR: Failed to parse questions response: {e}")
            return []
    
    def _get_default_questions(self, case_details: Dict[str, Any], 
                              investigation_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate default questions if AI generation fails."""
        print("INFO: Using default questions as fallback")
        
        # Extract indicators from context
        indicators = investigation_context.get("initial_indicators", [])
        indicator_summary = ", ".join([f"{ind.get('type', 'unknown')}: {ind.get('value', 'N/A')}" for ind in indicators])
        
        default_questions = [
            {
                "id": "Q001",
                "category": "initial_assessment",
                "priority": "critical",
                "question": f"What triggered this {investigation_context.get('investigation_type', 'security')} investigation and when did the suspicious activity begin?",
                "rationale": "Understanding the initial detection is crucial for investigation scope",
                "investigation_areas": ["all"],
                "expected_evidence_types": ["alerts", "logs", "detections"]
            },
            {
                "id": "Q002",
                "category": "initial_assessment",
                "priority": "critical", 
                "question": f"Are the indicators ({indicator_summary}) associated with known threats or campaigns?",
                "rationale": "Threat intelligence context helps understand adversary TTPs",
                "investigation_areas": ["ioc_enrichment", "threat_intelligence"],
                "expected_evidence_types": ["threat_intel_reports", "ioc_matches"]
            },
            {
                "id": "Q003", 
                "category": "technical_analysis",
                "priority": "critical",
                "question": "What systems, accounts, and processes are confirmed to be compromised or exhibiting suspicious behavior?",
                "rationale": "Scope determination is critical for containment",
                "investigation_areas": ["network_analysis", "endpoint_investigation", "log_correlation"],
                "expected_evidence_types": ["authentication_logs", "process_logs", "network_traffic"]
            },
            {
                "id": "Q004",
                "category": "technical_analysis",
                "priority": "high",
                "question": "What persistence mechanisms or backdoors have been established?",
                "rationale": "Identifying persistence is crucial for complete remediation",
                "investigation_areas": ["endpoint_investigation", "network_analysis"],
                "expected_evidence_types": ["registry_modifications", "scheduled_tasks", "service_installations"]
            },
            {
                "id": "Q005",
                "category": "technical_analysis",
                "priority": "high",
                "question": "What lateral movement or privilege escalation activities occurred?",
                "rationale": "Understanding attack progression helps assess full scope",
                "investigation_areas": ["log_correlation", "network_analysis", "endpoint_investigation"],
                "expected_evidence_types": ["authentication_logs", "process_creation", "network_connections"]
            },
            {
                "id": "Q006",
                "category": "impact_assessment", 
                "priority": "high",
                "question": "What sensitive data, systems, or credentials may have been accessed or exfiltrated?",
                "rationale": "Understanding data exposure for regulatory and business impact",
                "investigation_areas": ["endpoint_investigation", "log_correlation", "network_analysis"],
                "expected_evidence_types": ["file_access_logs", "database_logs", "network_traffic", "data_staging"]
            },
            {
                "id": "Q007",
                "category": "impact_assessment",
                "priority": "medium",
                "question": "What is the business impact and are any critical services affected?",
                "rationale": "Business context drives response prioritization",
                "investigation_areas": ["all"],
                "expected_evidence_types": ["service_logs", "availability_metrics"]
            },
            {
                "id": "Q008",
                "category": "attribution",
                "priority": "medium",
                "question": "What attack techniques (MITRE ATT&CK) and tools were used?",
                "rationale": "TTP analysis helps with attribution and defense improvements",
                "investigation_areas": ["all"],
                "expected_evidence_types": ["malware_samples", "tool_artifacts", "command_history"]
            },
            {
                "id": "Q009",
                "category": "response",
                "priority": "critical",
                "question": "What immediate containment actions should be taken?",
                "rationale": "Quick containment prevents further damage",
                "investigation_areas": ["all"],
                "expected_evidence_types": ["compromise_indicators", "affected_systems"]
            },
            {
                "id": "Q010",
                "category": "response",
                "priority": "high",
                "question": "What evidence needs to be preserved for forensics or legal purposes?",
                "rationale": "Evidence preservation is crucial for thorough investigation",
                "investigation_areas": ["all"],
                "expected_evidence_types": ["memory_dumps", "disk_images", "log_archives"]
            }
        ]
        
        return default_questions
    
    async def update_questions_with_findings(self, questions: List[Dict[str, Any]], 
                                           findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Update questions based on investigation findings to add new questions or mark answered."""
        # This could be enhanced to use AI to determine which questions are answered
        # and generate follow-up questions based on findings
        
        updated_questions = questions.copy()
        
        # Simple logic to mark questions as potentially answered based on findings
        for question in updated_questions:
            question["status"] = "pending"  # Default status
            question["related_findings"] = []
            
            # Check if findings relate to this question
            for area, area_findings in findings.items():
                if area in question.get("investigation_areas", []):
                    if area_findings:  # If there are findings in this area
                        question["related_findings"].append(area)
        
        return updated_questions