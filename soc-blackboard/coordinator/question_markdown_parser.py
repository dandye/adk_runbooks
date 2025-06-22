"""
Markdown parser for hierarchical investigation questions.

Parses markdown-formatted questions with sub-bullets into structured question objects.
"""

import re
from typing import Dict, List, Any, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class QuestionMarkdownParser:
    """Parse markdown-formatted questions into hierarchical question objects."""
    
    def __init__(self):
        # Pattern to match question IDs like Q001, Q001.1, etc.
        self.id_pattern = re.compile(r'^(Q\d{3}(?:\.\d+)?)\s*$', re.MULTILINE)
        # Pattern to match category/priority/etc labels
        self.label_pattern = re.compile(r'^(category|priority|rationale|investigation areas?|expected evidence):\s*(.+)$', re.IGNORECASE | re.MULTILINE)
        
    def parse_markdown_questions(self, markdown_text: str) -> List[Dict[str, Any]]:
        """
        Parse markdown text containing hierarchical questions.
        
        Expected format:
        ```
        Q001
        category: initial_assessment
        priority: critical
        What triggered this investigation?
        rationale: Understanding the initial detection is crucial
        investigation areas: all
        expected evidence: alerts, logs
        
        Q002
        category: initial_assessment
        priority: critical
        Are the indicators associated with known threats?
        rationale: Threat intelligence context helps understand adversary TTPs
        investigation areas: ioc_enrichment, threat_intelligence
        expected evidence: threat_intel_reports, ioc_matches
        
        - Q002.1
          Is the indicator (ip: 192.168.30.20) associated with known threats?
          
        - Q002.2
          Is the indicator (domain: SUPERSTARTS.TOP) associated with known threats?
        ```
        
        Args:
            markdown_text: The markdown text to parse
            
        Returns:
            List of question dictionaries
        """
        questions = []
        current_parent = None
        
        # Split by question IDs
        sections = self._split_by_questions(markdown_text)
        
        for section in sections:
            question = self._parse_question_section(section)
            if question:
                # Check if this is a sub-question
                if '.' in question['id'] and len(question['id'].split('.')) == 2:
                    # It's a sub-question
                    parent_id = question['id'].split('.')[0]
                    question['parent_id'] = parent_id
                    
                    # Inherit properties from parent if not specified
                    parent = self._find_parent(questions, parent_id)
                    if parent:
                        for key in ['category', 'priority', 'investigation_areas', 'expected_evidence_types']:
                            if key not in question or not question.get(key):
                                question[key] = parent.get(key)
                        # For rationale, inherit from parent if using default
                        if question.get('rationale') == 'Systematic investigation' and parent.get('rationale'):
                            question['rationale'] = f"Specific analysis for {parent.get('rationale', '').lower()}"
                
                questions.append(question)
        
        return questions
    
    def _split_by_questions(self, markdown_text: str) -> List[str]:
        """Split markdown text into individual question sections."""
        sections = []
        
        # Find all question IDs and their positions, including sub-questions
        pattern = re.compile(r'^(?:[-•]\s*)?(Q\d{3}(?:\.\d+)?)\s*$', re.MULTILINE)
        matches = list(pattern.finditer(markdown_text))
        
        for i, match in enumerate(matches):
            start = match.start()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(markdown_text)
            section = markdown_text[start:end].strip()
            sections.append(section)
        
        return sections
    
    def _parse_question_section(self, section: str) -> Optional[Dict[str, Any]]:
        """Parse a single question section."""
        if not section:
            return None
        
        lines = section.split('\n')
        question_dict = {}
        
        # First line should be the question ID
        id_match = self.id_pattern.match(lines[0])
        if not id_match:
            # Check if it's a sub-question format (- Q002.1)
            sub_match = re.match(r'^[-•]\s*(Q\d{3}\.\d+)\s*$', lines[0])
            if sub_match:
                question_dict['id'] = sub_match.group(1)
                lines = lines[1:]  # Remove the ID line
            else:
                return None
        else:
            question_dict['id'] = id_match.group(1)
            lines = lines[1:]  # Remove the ID line
        
        # Parse the rest of the section
        question_text = None
        current_field = None
        field_values = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Check for labeled fields
            label_match = self.label_pattern.match(line)
            if label_match:
                # Save previous field if any
                if current_field and field_values:
                    self._save_field(question_dict, current_field, field_values)
                    field_values = []
                
                field_name = label_match.group(1).lower()
                value = label_match.group(2).strip()
                
                # Special handling for priority - it should only be the priority level
                if field_name == 'priority' and ' ' in value:
                    # Split on first space - priority level and rest of line
                    parts = value.split(' ', 1)
                    priority_value = parts[0]
                    rest_of_line = parts[1] if len(parts) > 1 else ''
                    
                    # Save the priority
                    self._save_field(question_dict, 'priority', [priority_value])
                    
                    # The rest is likely the question
                    if rest_of_line and rest_of_line.endswith('?'):
                        question_text = rest_of_line
                    current_field = None  # Don't continue with this field
                else:
                    current_field = field_name
                    if value:
                        field_values.append(value)
            elif line.startswith('- ') or line.startswith('• '):
                # It's a bullet point for the current field
                if current_field:
                    field_values.append(line[2:].strip())
            elif not question_text and not current_field and line.endswith('?'):
                # This is likely the question text (ends with ?)
                question_text = line
            elif current_field:
                # Continuation of the current field
                field_values.append(line)
            elif not question_text:
                # This might be the question text if it doesn't end with ?
                question_text = line
        
        # Save any remaining field
        if current_field and field_values:
            self._save_field(question_dict, current_field, field_values)
        
        # Set the question text
        if question_text:
            question_dict['question'] = question_text
        
        # Fix priority if it contains the question
        if 'priority' in question_dict and ' ' in question_dict['priority']:
            priority_value = question_dict['priority']
            parts = priority_value.split(' ', 1)
            if len(parts) > 1 and parts[1].strip():
                question_dict['priority'] = parts[0]
                if not question_text and parts[1].endswith('?'):
                    question_text = parts[1]
                    question_dict['question'] = question_text
        
        # Ensure required fields have defaults
        if 'category' not in question_dict:
            question_dict['category'] = 'technical_analysis'
        if 'priority' not in question_dict:
            question_dict['priority'] = 'medium'
        if 'rationale' not in question_dict:
            question_dict['rationale'] = 'Systematic investigation'
        
        return question_dict
    
    def _save_field(self, question_dict: Dict[str, Any], field_name: str, values: List[str]):
        """Save a field to the question dictionary."""
        # Normalize field names
        field_map = {
            'category': 'category',
            'priority': 'priority',
            'rationale': 'rationale',
            'investigation areas': 'investigation_areas',
            'investigation area': 'investigation_areas',
            'expected evidence': 'expected_evidence_types'
        }
        
        normalized_field = field_map.get(field_name, field_name)
        
        if normalized_field in ['investigation_areas', 'expected_evidence_types']:
            # These are lists - split by commas
            all_values = []
            for value in values:
                all_values.extend([v.strip() for v in value.split(',')])
            question_dict[normalized_field] = all_values
        elif len(values) == 1:
            question_dict[normalized_field] = values[0]
        else:
            question_dict[normalized_field] = ' '.join(values)
    
    def _find_parent(self, questions: List[Dict[str, Any]], parent_id: str) -> Optional[Dict[str, Any]]:
        """Find a parent question by ID."""
        for q in questions:
            if q['id'] == parent_id:
                return q
        return None
    
    def format_questions_as_markdown(self, questions: List[Dict[str, Any]]) -> str:
        """
        Format questions back to markdown format.
        
        Args:
            questions: List of question dictionaries
            
        Returns:
            Markdown-formatted string
        """
        output = []
        
        # Group by parent
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
            output.append(f"category: {parent.get('category', 'unknown')}")
            output.append(f"priority: {parent.get('priority', 'medium')}")
            output.append(parent['question'])
            
            if parent.get('rationale'):
                output.append(f"rationale: {parent['rationale']}")
            
            if parent.get('investigation_areas'):
                areas = ', '.join(parent['investigation_areas'])
                output.append(f"investigation areas: {areas}")
            
            if parent.get('expected_evidence_types'):
                evidence = ', '.join(parent['expected_evidence_types'])
                output.append(f"expected evidence: {evidence}")
            
            output.append("")  # Blank line
            
            # Format sub-questions if any
            if parent_id in sub_questions:
                for sub_q in sorted(sub_questions[parent_id], key=lambda x: x['id']):
                    output.append(f"- {sub_q['id']}")
                    output.append(f"  {sub_q['question']}")
                    if sub_q.get('indicator'):
                        output.append(f"  indicator: {sub_q['indicator']['type']}: {sub_q['indicator']['value']}")
                    output.append("")  # Blank line between sub-questions
        
        return '\n'.join(output)