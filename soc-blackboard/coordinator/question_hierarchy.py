"""
Question hierarchy processor for investigation questions.

This module handles the creation of hierarchical questions (Q001, Q001.1, Q001.2, etc.)
from multi-indicator or complex questions.
"""

import re
from typing import Dict, List, Any, Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class QuestionHierarchyProcessor:
    """Process questions to create hierarchical sub-questions."""
    
    def __init__(self):
        self.indicator_patterns = {
            'ip': re.compile(r'\b(?:ip:\s*)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'),
            'domain': re.compile(r'\b(?:domain:\s*)?([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,})\b', re.IGNORECASE),
            'hash': re.compile(r'\b(?:hash:\s*)?([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b'),
            'filepath': re.compile(r'\b(?:filepath:\s*)?((?:[A-Za-z]:|\\\\)(?:\\\\[^\\/:*?"<>|\r\n]+)+(?:\.[a-zA-Z0-9]+)?)\b'),
            'hostname': re.compile(r'\b(?:hostname:\s*)?([A-Za-z0-9][A-Za-z0-9-]{0,62})\b')
        }
    
    def process_questions(self, questions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process a list of questions to create hierarchical sub-questions.
        
        Args:
            questions: List of question dictionaries
            
        Returns:
            List of questions including parent and sub-questions
        """
        processed_questions = []
        
        for question in questions:
            # Always include the parent question
            processed_questions.append(question)
            
            # Check if this question should be split into sub-questions
            sub_questions = self._create_sub_questions(question)
            processed_questions.extend(sub_questions)
        
        return processed_questions
    
    def _create_sub_questions(self, parent_question: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Create sub-questions from a parent question if it contains multiple indicators.
        
        Args:
            parent_question: The parent question dictionary
            
        Returns:
            List of sub-question dictionaries
        """
        question_text = parent_question.get('question', '')
        
        # Extract all indicators from the question
        indicators = self._extract_indicators(question_text)
        
        # Only create sub-questions if there are multiple indicators
        if len(indicators) <= 1:
            return []
        
        # Check if this is a question type that should be split
        if not self._should_split_question(question_text, indicators):
            return []
        
        sub_questions = []
        parent_id = parent_question.get('id', 'Q001')
        
        for idx, (indicator_type, indicator_value) in enumerate(indicators, 1):
            sub_question = self._create_single_indicator_question(
                parent_question, 
                parent_id,
                idx,
                indicator_type,
                indicator_value
            )
            sub_questions.append(sub_question)
        
        return sub_questions
    
    def _extract_indicators(self, text: str) -> List[Tuple[str, str]]:
        """
        Extract all indicators from a text string.
        
        Args:
            text: The text to extract indicators from
            
        Returns:
            List of tuples (indicator_type, indicator_value)
        """
        indicators = []
        
        # Look for explicitly typed indicators first (e.g., "ip: 1.2.3.4")
        typed_pattern = re.compile(r'\b(ip|domain|hash|filepath|hostname):\s*([^\s,\)]+)')
        for match in typed_pattern.finditer(text):
            indicator_type = match.group(1)
            indicator_value = match.group(2)
            indicators.append((indicator_type, indicator_value))
        
        # If no explicitly typed indicators found, try to detect by pattern
        if not indicators:
            for indicator_type, pattern in self.indicator_patterns.items():
                for match in pattern.finditer(text):
                    # Skip if this indicator was already found with explicit typing
                    indicator_value = match.group(1) if match.groups() else match.group(0)
                    if not any(iv == indicator_value for _, iv in indicators):
                        indicators.append((indicator_type, indicator_value))
        
        return indicators
    
    def _should_split_question(self, question_text: str, indicators: List[Tuple[str, str]]) -> bool:
        """
        Determine if a question should be split into sub-questions.
        
        Args:
            question_text: The question text
            indicators: List of indicators found in the question
            
        Returns:
            True if the question should be split
        """
        # Keywords that suggest the question is asking about individual indicators
        split_keywords = [
            'associated with',
            'reputation',
            'known threats',
            'malicious',
            'legitimate',
            'attributed to',
            'related to',
            'connected to',
            'seen in',
            'reported in'
        ]
        
        question_lower = question_text.lower()
        return any(keyword in question_lower for keyword in split_keywords)
    
    def _create_single_indicator_question(
        self, 
        parent_question: Dict[str, Any],
        parent_id: str,
        sub_index: int,
        indicator_type: str,
        indicator_value: str
    ) -> Dict[str, Any]:
        """
        Create a sub-question for a single indicator.
        
        Args:
            parent_question: The parent question dictionary
            parent_id: The parent question ID (e.g., "Q002")
            sub_index: The sub-question index (1, 2, 3, etc.)
            indicator_type: Type of the indicator
            indicator_value: Value of the indicator
            
        Returns:
            Sub-question dictionary
        """
        # Create the sub-question ID
        sub_id = f"{parent_id}.{sub_index}"
        
        # Extract the core question and replace with single indicator
        original_question = parent_question.get('question', '')
        
        # Find and replace the indicators list with the single indicator
        # Pattern to match indicator lists in parentheses
        list_pattern = re.compile(r'\([^)]*(?:ip:|domain:|hash:|filepath:|hostname:)[^)]*\)')
        
        # Replace the list with the single indicator
        new_question = list_pattern.sub(f'({indicator_type}: {indicator_value})', original_question)
        
        # If no parentheses list found, try to replace inline indicators
        if new_question == original_question:
            # Replace "indicators" with "indicator"
            new_question = re.sub(r'\bindicators\b', 'indicator', original_question, flags=re.IGNORECASE)
            # Add the specific indicator at the end
            new_question = new_question.rstrip('?') + f' ({indicator_type}: {indicator_value})?'
        
        # Create the sub-question
        sub_question = {
            'id': sub_id,
            'parent_id': parent_id,
            'category': parent_question.get('category', 'technical_analysis'),
            'priority': parent_question.get('priority', 'high'),
            'question': new_question,
            'rationale': f"Specific analysis of {indicator_type} indicator",
            'investigation_areas': parent_question.get('investigation_areas', []),
            'expected_evidence_types': parent_question.get('expected_evidence_types', []),
            'indicator': {
                'type': indicator_type,
                'value': indicator_value
            }
        }
        
        return sub_question
    
    def format_questions_for_display(self, questions: List[Dict[str, Any]]) -> str:
        """
        Format questions in the hierarchical display format.
        
        Args:
            questions: List of question dictionaries
            
        Returns:
            Formatted string representation
        """
        output = []
        
        # Group questions by parent
        parent_questions = {}
        sub_questions = {}
        
        for q in questions:
            if 'parent_id' in q:
                parent_id = q['parent_id']
                if parent_id not in sub_questions:
                    sub_questions[parent_id] = []
                sub_questions[parent_id].append(q)
            else:
                parent_questions[q['id']] = q
        
        # Format each parent with its sub-questions
        for parent_id in sorted(parent_questions.keys()):
            parent = parent_questions[parent_id]
            
            # Format parent question
            output.append(f"{parent['id']}")
            output.append(parent.get('category', 'unknown'))
            output.append(parent.get('priority', 'medium'))
            output.append(parent['question'])
            
            if parent.get('rationale'):
                output.append(parent['rationale'])
            
            if parent.get('investigation_areas'):
                output.append("Investigation Areas")
                for area in parent['investigation_areas']:
                    output.append(area)
            
            if parent.get('expected_evidence_types'):
                output.append("Expected Evidence")
                for evidence in parent['expected_evidence_types']:
                    output.append(evidence)
            
            output.append("")  # Blank line
            
            # Format sub-questions if any
            if parent_id in sub_questions:
                for sub_q in sorted(sub_questions[parent_id], key=lambda x: x['id']):
                    output.append(f"{sub_q['id']}")
                    output.append(sub_q.get('category', 'unknown'))
                    output.append(sub_q.get('priority', 'medium'))
                    output.append(sub_q['question'])
                    output.append("")  # Blank line between sub-questions
        
        return '\n'.join(output)