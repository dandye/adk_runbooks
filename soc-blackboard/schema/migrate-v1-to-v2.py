#!/usr/bin/env python3
"""
Migration utility to convert SOC blackboard data from v1 to v2 schema format.

Usage:
    python migrate-v1-to-v2.py input.json output.json
    python migrate-v1-to-v2.py --validate-only input.json
"""

import json
import sys
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import uuid

def extract_questions_from_v1(v1_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract questions from v1 format and convert to v2 format."""
    knowledge_areas = v1_data.get('knowledge_areas', {})
    questions_data = knowledge_areas.get('investigation_questions', [])
    
    questions = []
    errors = []
    summary = {
        "total_count": 0,
        "by_category": {},
        "by_priority": {},
        "generated_at": None
    }
    
    if isinstance(questions_data, list):
        # Process v1 list format
        for item in questions_data:
            if not isinstance(item, dict) or 'finding' not in item:
                continue
                
            finding = item['finding']
            finding_type = finding.get('type', '')
            
            # Extract questions from questions_batch findings
            if finding_type == 'questions_batch':
                # Original questions
                original_questions = finding.get('original_questions', [])
                for q in original_questions:
                    if isinstance(q, dict):
                        questions.append({
                            "id": q.get('id', str(uuid.uuid4())),
                            "question": q.get('question', ''),
                            "category": q.get('category', 'general'),
                            "priority": q.get('priority', 'medium'),
                            "rationale": q.get('rationale', ''),
                            "investigation_areas": q.get('investigation_areas', []),
                            "expected_evidence_types": q.get('expected_evidence_types', []),
                            "created_at": item.get('timestamp', finding.get('generated_at', datetime.now().isoformat())),
                            "created_by": item.get('agent', 'unknown')
                        })
                
                # Enhanced questions (merge enhancement data)
                enhanced_questions = finding.get('enhanced_questions', [])
                for eq in enhanced_questions:
                    if isinstance(eq, dict):
                        # Find matching original question or create new
                        existing_q = None
                        for q in questions:
                            if q['id'] == eq.get('id'):
                                existing_q = q
                                break
                        
                        if existing_q:
                            # Add enhancement data to existing question
                            existing_q['enhancement'] = {
                                "available_tools": eq.get('available_tools', []),
                                "suggested_approach": eq.get('suggested_approach', ''),
                                "tool_wishlist": eq.get('tool_wishlist', []),
                                "data_sources_needed": eq.get('data_sources_needed', []),
                                "alternative_methods": eq.get('alternative_methods', [])
                            }
                        else:
                            # Create new question with enhancement
                            new_question = {
                                "id": eq.get('id', str(uuid.uuid4())),
                                "question": eq.get('question', ''),
                                "category": eq.get('category', 'general'),
                                "priority": eq.get('priority', 'medium'),
                                "rationale": eq.get('rationale', ''),
                                "investigation_areas": eq.get('investigation_areas', []),
                                "expected_evidence_types": eq.get('expected_evidence_types', []),
                                "created_at": item.get('timestamp', finding.get('generated_at', datetime.now().isoformat())),
                                "created_by": item.get('agent', 'unknown'),
                                "enhancement": {
                                    "available_tools": eq.get('available_tools', []),
                                    "suggested_approach": eq.get('suggested_approach', ''),
                                    "tool_wishlist": eq.get('tool_wishlist', []),
                                    "data_sources_needed": eq.get('data_sources_needed', []),
                                    "alternative_methods": eq.get('alternative_methods', [])
                                }
                            }
                            questions.append(new_question)
                
                # Set generated_at from this finding
                summary["generated_at"] = finding.get('generated_at') or item.get('timestamp')
            
            # Extract individual question findings
            elif finding_type == 'investigation_question':
                questions.append({
                    "id": finding.get('question_id', item.get('id', str(uuid.uuid4()))),
                    "question": finding.get('question', ''),
                    "category": finding.get('category', 'general'),
                    "priority": finding.get('priority', 'medium'),
                    "rationale": finding.get('rationale', ''),
                    "investigation_areas": finding.get('investigation_areas', []),
                    "expected_evidence_types": finding.get('expected_evidence_types', []),
                    "created_at": item.get('timestamp', datetime.now().isoformat()),
                    "created_by": item.get('agent', 'unknown')
                })
            
            # Convert error findings to processing errors
            elif finding_type in ['tool_mapping_error', 'questions_summary']:
                if finding_type == 'tool_mapping_error':
                    errors.append({
                        "id": item.get('id', str(uuid.uuid4())),
                        "timestamp": item.get('timestamp', datetime.now().isoformat()),
                        "agent": item.get('agent', 'unknown'),
                        "operation": "question_processing",
                        "error_type": finding.get('error_type', 'Unknown'),
                        "message": finding.get('error', 'Unknown error'),
                        "context": {
                            "original_finding_type": finding_type,
                            "original_data": finding
                        }
                    })
    
    # Calculate summary statistics
    summary["total_count"] = len(questions)
    for q in questions:
        category = q.get('category', 'unknown')
        priority = q.get('priority', 'unknown')
        summary["by_category"][category] = summary["by_category"].get(category, 0) + 1
        summary["by_priority"][priority] = summary["by_priority"].get(priority, 0) + 1
    
    return {
        "summary": summary,
        "items": questions,
        "errors": errors
    }

def convert_findings_to_v2(v1_data: Dict[str, Any]) -> Dict[str, Any]:
    """Convert findings from v1 to v2 format."""
    knowledge_areas = v1_data.get('knowledge_areas', {})
    findings = {}
    
    # Define the knowledge areas that contain findings
    finding_areas = [
        'network_analysis', 'endpoint_behaviors', 'log_correlations',
        'ioc_enrichments', 'timeline_events', 'threat_intelligence'
    ]
    
    for area in finding_areas:
        area_findings = knowledge_areas.get(area, [])
        converted_findings = []
        
        for finding in area_findings:
            if isinstance(finding, dict):
                # Convert v1 finding to v2 format
                v2_finding = {
                    "id": finding.get('id', str(uuid.uuid4())),
                    "timestamp": finding.get('timestamp', datetime.now().isoformat()),
                    "agent": finding.get('agent', 'unknown'),
                    "area": finding.get('area', area),
                    "type": finding.get('finding', {}).get('type', 'unknown') if 'finding' in finding else 'unknown',
                    "data": finding.get('finding', {}),
                    "confidence": finding.get('confidence', 'medium'),
                    "tags": finding.get('tags', []),
                    "metadata": finding.get('metadata', {})
                }
                
                # Clean up data field - remove redundant type field
                if 'type' in v2_finding['data']:
                    del v2_finding['data']['type']
                
                converted_findings.append(v2_finding)
        
        findings[area] = converted_findings
    
    return findings

def extract_processing_info(v1_data: Dict[str, Any], question_errors: List[Dict]) -> Dict[str, Any]:
    """Extract processing information and combine with question processing errors."""
    # Start with question processing errors
    all_errors = question_errors.copy()
    
    # Try to extract agent status from investigation metadata
    investigation_metadata = v1_data.get('knowledge_areas', {}).get('investigation_metadata', {})
    
    agents = {}
    
    # If there's error information in metadata, extract it
    if 'error' in investigation_metadata:
        all_errors.append({
            "id": str(uuid.uuid4()),
            "timestamp": investigation_metadata.get('completed_at', datetime.now().isoformat()),
            "agent": investigation_metadata.get('investigator', 'unknown'),
            "operation": "investigation",
            "error_type": investigation_metadata.get('type', 'Unknown'),
            "message": investigation_metadata.get('error', 'Unknown error'),
            "context": {
                "investigation_context": investigation_metadata.get('context', {})
            }
        })
    
    # Determine agent status based on available data
    if investigation_metadata.get('status') == 'completed':
        agents['coordinator'] = {
            "status": "completed",
            "last_run": investigation_metadata.get('completed_at', datetime.now().isoformat())
        }
    else:
        agents['coordinator'] = {
            "status": "active" if not all_errors else "failed",
            "last_run": datetime.now().isoformat()
        }
    
    return {
        "agents": agents,
        "errors": all_errors
    }

def migrate_v1_to_v2(v1_data: Dict[str, Any]) -> Dict[str, Any]:
    """Migrate complete v1 investigation data to v2 format."""
    
    # Extract investigation metadata
    investigation_id = v1_data.get('investigation_id') or v1_data.get('knowledge_areas', {}).get('investigation_metadata', {}).get('investigation_id', 'unknown')
    created_at = v1_data.get('created_at', datetime.now().isoformat())
    updated_at = v1_data.get('saved_at', datetime.now().isoformat())
    
    # Extract case context
    case_context = {}
    metadata = v1_data.get('knowledge_areas', {}).get('investigation_metadata', {})
    if 'case_context' in metadata:
        case_context = metadata['case_context']
    else:
        # Build case context from available metadata
        case_context = {
            "case_id": metadata.get('case_id', investigation_id),
            "title": metadata.get('title', 'Unknown'),
            "priority": metadata.get('priority', 'medium'),
            "initial_indicators": metadata.get('initial_indicators', []),
            "data_sources": metadata.get('data_sources', []),
            "investigation_type": metadata.get('investigation_type', 'unknown')
        }
    
    # Convert questions
    questions_result = extract_questions_from_v1(v1_data)
    
    # Convert findings
    findings = convert_findings_to_v2(v1_data)
    
    # Extract processing info
    processing = extract_processing_info(v1_data, questions_result['errors'])
    
    # Extract risk scores
    risk_scores = v1_data.get('knowledge_areas', {}).get('risk_scores', {})
    if risk_scores:
        risk_scores['calculated_at'] = datetime.now().isoformat()
    
    # Build v2 structure
    v2_data = {
        "schema_version": "2.0",
        "investigation": {
            "id": investigation_id,
            "created_at": created_at,
            "updated_at": updated_at,
            "status": "active",  # Default, can be refined based on processing info
            "case_context": case_context
        },
        "questions": {
            "summary": questions_result['summary'],
            "items": questions_result['items']
        },
        "findings": findings,
        "processing": processing
    }
    
    if risk_scores:
        v2_data["risk_scores"] = risk_scores
    
    return v2_data

def validate_v2_data(v2_data: Dict[str, Any]) -> List[str]:
    """Basic validation of v2 data structure."""
    errors = []
    
    # Check required top-level fields
    required_fields = ['schema_version', 'investigation', 'questions', 'findings', 'processing']
    for field in required_fields:
        if field not in v2_data:
            errors.append(f"Missing required field: {field}")
    
    # Check schema version
    if v2_data.get('schema_version') != '2.0':
        errors.append(f"Invalid schema version: {v2_data.get('schema_version')}")
    
    # Check investigation structure
    investigation = v2_data.get('investigation', {})
    required_inv_fields = ['id', 'created_at', 'updated_at', 'status']
    for field in required_inv_fields:
        if field not in investigation:
            errors.append(f"Missing investigation field: {field}")
    
    # Check questions structure
    questions = v2_data.get('questions', {})
    if 'summary' not in questions or 'items' not in questions:
        errors.append("Questions section missing 'summary' or 'items'")
    
    # Check processing structure
    processing = v2_data.get('processing', {})
    if 'agents' not in processing or 'errors' not in processing:
        errors.append("Processing section missing 'agents' or 'errors'")
    
    return errors

def main():
    parser = argparse.ArgumentParser(description='Migrate SOC blackboard data from v1 to v2 schema')
    parser.add_argument('input_file', help='Input JSON file (v1 format)')
    parser.add_argument('output_file', nargs='?', help='Output JSON file (v2 format)')
    parser.add_argument('--validate-only', action='store_true', help='Only validate conversion, do not write output')
    parser.add_argument('--pretty', action='store_true', help='Pretty-print JSON output')
    
    args = parser.parse_args()
    
    # Read input file
    try:
        with open(args.input_file, 'r') as f:
            v1_data = json.load(f)
    except Exception as e:
        print(f"Error reading input file: {e}")
        sys.exit(1)
    
    # Perform migration
    try:
        v2_data = migrate_v1_to_v2(v1_data)
    except Exception as e:
        print(f"Error during migration: {e}")
        sys.exit(1)
    
    # Validate result
    validation_errors = validate_v2_data(v2_data)
    if validation_errors:
        print("Validation errors:")
        for error in validation_errors:
            print(f"  - {error}")
        if not args.validate_only:
            print("Migration completed with validation errors.")
    else:
        print("Validation successful.")
    
    # Write output file (unless validate-only)
    if not args.validate_only and args.output_file:
        try:
            with open(args.output_file, 'w') as f:
                if args.pretty:
                    json.dump(v2_data, f, indent=2, ensure_ascii=False)
                else:
                    json.dump(v2_data, f, ensure_ascii=False)
            print(f"Migration completed. Output written to: {args.output_file}")
        except Exception as e:
            print(f"Error writing output file: {e}")
            sys.exit(1)
    elif args.validate_only:
        print("Validation-only mode. No output file written.")
    else:
        # Print to stdout
        if args.pretty:
            print(json.dumps(v2_data, indent=2, ensure_ascii=False))
        else:
            print(json.dumps(v2_data, ensure_ascii=False))

if __name__ == '__main__':
    main()