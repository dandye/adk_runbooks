"""
Schema utilities for SOC blackboard investigation data.
Provides schema detection, validation, and conversion utilities.
"""

import json
import jsonschema
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple


def detect_schema_version(data: Dict[str, Any]) -> str:
    """
    Detect the schema version of investigation data.
    
    Args:
        data: Investigation data dictionary
        
    Returns:
        Schema version string ('1.x', '2.0', or 'unknown')
    """
    # Check for explicit schema version (v2.0+)
    if 'schema_version' in data:
        return data['schema_version']
    
    # Check for v1.x characteristics
    if 'knowledge_areas' in data and 'investigation' not in data:
        return '1.x'
    
    # Check for v2.0 characteristics without explicit version
    if all(key in data for key in ['investigation', 'questions', 'findings', 'processing']):
        return '2.0'
    
    return 'unknown'


def load_schema(schema_version: str = '2.0') -> Dict[str, Any]:
    """
    Load JSON schema for validation.
    
    Args:
        schema_version: Schema version to load ('2.0')
        
    Returns:
        JSON schema dictionary
        
    Raises:
        FileNotFoundError: If schema file not found
        json.JSONDecodeError: If schema file invalid
    """
    schema_file = Path(__file__).parent.parent / 'schema' / f'investigation-schema-v{schema_version}.json'
    
    if not schema_file.exists():
        raise FileNotFoundError(f"Schema file not found: {schema_file}")
    
    with open(schema_file, 'r') as f:
        return json.load(f)


def validate_investigation_data(data: Dict[str, Any], schema_version: Optional[str] = None) -> Tuple[bool, List[str]]:
    """
    Validate investigation data against schema.
    
    Args:
        data: Investigation data to validate
        schema_version: Schema version to validate against (auto-detected if None)
        
    Returns:
        Tuple of (is_valid, error_messages)
    """
    if schema_version is None:
        schema_version = detect_schema_version(data)
    
    if schema_version == '1.x':
        # Basic v1.x validation (no formal schema)
        return validate_v1_data(data)
    elif schema_version == '2.0':
        # Full JSON schema validation for v2.0
        try:
            schema = load_schema('2.0')
            jsonschema.validate(data, schema)
            return True, []
        except jsonschema.ValidationError as e:
            return False, [str(e)]
        except Exception as e:
            return False, [f"Schema validation error: {str(e)}"]
    else:
        return False, [f"Unknown schema version: {schema_version}"]


def validate_v1_data(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Basic validation for v1.x data format.
    
    Args:
        data: v1.x investigation data
        
    Returns:
        Tuple of (is_valid, error_messages)
    """
    errors = []
    
    # Check for required top-level fields
    if 'knowledge_areas' not in data:
        errors.append("Missing 'knowledge_areas' field")
    
    # Check for basic timestamp fields
    if 'created_at' not in data:
        errors.append("Missing 'created_at' field")
    
    return len(errors) == 0, errors


def extract_questions_v2(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract questions from v2.0 format data.
    
    Args:
        data: v2.0 investigation data
        
    Returns:
        Questions data with summary and items
    """
    if detect_schema_version(data) != '2.0':
        raise ValueError("Data is not in v2.0 format")
    
    return data.get('questions', {'summary': {'total_count': 0}, 'items': []})


def extract_questions_v1(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract questions from v1.x format data (legacy compatibility).
    
    Args:
        data: v1.x investigation data
        
    Returns:
        Questions data in v2.0 format
    """
    knowledge_areas = data.get('knowledge_areas', {})
    questions_data = knowledge_areas.get('investigation_questions', [])
    
    questions = []
    
    if isinstance(questions_data, list):
        for item in questions_data:
            if isinstance(item, dict) and 'finding' in item:
                finding = item['finding']
                finding_type = finding.get('type', '')
                
                # Extract from questions_batch
                if finding_type == 'questions_batch':
                    original_questions = finding.get('original_questions', [])
                    enhanced_questions = finding.get('enhanced_questions', [])
                    
                    # Process original questions
                    for q in original_questions:
                        if isinstance(q, dict):
                            questions.append({
                                "id": q.get('id', 'unknown'),
                                "question": q.get('question', ''),
                                "category": q.get('category', 'general'),
                                "priority": q.get('priority', 'medium'),
                                "rationale": q.get('rationale', ''),
                                "investigation_areas": q.get('investigation_areas', []),
                                "expected_evidence_types": q.get('expected_evidence_types', []),
                                "created_at": item.get('timestamp', ''),
                                "created_by": item.get('agent', 'unknown')
                            })
                    
                    # Add enhancement data
                    for eq in enhanced_questions:
                        if isinstance(eq, dict):
                            # Find matching question
                            for q in questions:
                                if q['id'] == eq.get('id'):
                                    q['enhancement'] = {
                                        "available_tools": eq.get('available_tools', []),
                                        "suggested_approach": eq.get('suggested_approach', ''),
                                        "tool_wishlist": eq.get('tool_wishlist', []),
                                        "data_sources_needed": eq.get('data_sources_needed', []),
                                        "alternative_methods": eq.get('alternative_methods', [])
                                    }
                                    break
    
    # Calculate summary
    summary = {
        "total_count": len(questions),
        "by_category": {},
        "by_priority": {},
        "generated_at": None
    }
    
    for q in questions:
        category = q.get('category', 'unknown')
        priority = q.get('priority', 'unknown')
        summary["by_category"][category] = summary["by_category"].get(category, 0) + 1
        summary["by_priority"][priority] = summary["by_priority"].get(priority, 0) + 1
    
    return {
        "summary": summary,
        "items": questions
    }


def extract_questions_any_format(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract questions from data in any supported format.
    
    Args:
        data: Investigation data (any version)
        
    Returns:
        Questions data in v2.0 format
    """
    schema_version = detect_schema_version(data)
    
    if schema_version == '2.0':
        return extract_questions_v2(data)
    elif schema_version == '1.x':
        return extract_questions_v1(data)
    else:
        # Return empty questions structure
        return {
            "summary": {
                "total_count": 0,
                "by_category": {},
                "by_priority": {},
                "generated_at": None
            },
            "items": []
        }


def get_processing_errors(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract processing errors from investigation data.
    
    Args:
        data: Investigation data (any version)
        
    Returns:
        List of processing error objects
    """
    schema_version = detect_schema_version(data)
    
    if schema_version == '2.0':
        return data.get('processing', {}).get('errors', [])
    elif schema_version == '1.x':
        # Extract errors from v1.x format (mixed with findings)
        errors = []
        knowledge_areas = data.get('knowledge_areas', {})
        questions_data = knowledge_areas.get('investigation_questions', [])
        
        if isinstance(questions_data, list):
            for item in questions_data:
                if isinstance(item, dict) and 'finding' in item:
                    finding = item['finding']
                    if finding.get('type') == 'tool_mapping_error':
                        errors.append({
                            "id": item.get('id', 'unknown'),
                            "timestamp": item.get('timestamp', ''),
                            "agent": item.get('agent', 'unknown'),
                            "operation": "question_processing",
                            "error_type": finding.get('error_type', 'Unknown'),
                            "message": finding.get('error', 'Unknown error'),
                            "context": {"original_finding": finding}
                        })
        
        return errors
    else:
        return []


def get_investigation_metadata(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract investigation metadata from data in any format.
    
    Args:
        data: Investigation data (any version)
        
    Returns:
        Investigation metadata dictionary
    """
    schema_version = detect_schema_version(data)
    
    if schema_version == '2.0':
        return data.get('investigation', {})
    elif schema_version == '1.x':
        # Extract from v1.x format
        investigation_id = data.get('investigation_id', 'unknown')
        created_at = data.get('created_at', '')
        updated_at = data.get('saved_at', '')
        
        metadata = data.get('knowledge_areas', {}).get('investigation_metadata', {})
        case_context = metadata.get('case_context', {})
        
        return {
            "id": investigation_id,
            "created_at": created_at,
            "updated_at": updated_at,
            "status": metadata.get('status', 'active'),
            "case_context": case_context
        }
    else:
        return {
            "id": "unknown",
            "created_at": "",
            "updated_at": "",
            "status": "unknown",
            "case_context": {}
        }