# SOC Blackboard Investigation Schema v2.0

## Overview

This document defines the improved JSON schema for SOC investigation blackboard data structure. This schema addresses persistent data structure issues and provides a clear, consistent format for investigation data.

## Current Problems (v1.x)

The existing schema has several critical issues:

1. **Inconsistent Question Storage**: Questions stored as:
   - `questions_batch` findings with arrays inside
   - Individual `investigation_question` findings
   - Mixed with `questions_summary` and `tool_mapping_error` findings

2. **Error Data Pollution**: Processing errors stored as findings alongside actual investigation data, causing:
   - Confusion in data processing
   - Difficulty in UI display logic
   - Coordinator errors like `"'dict' object has no attribute 'finding'"`

3. **Schema Inconsistency**: Same wrapper pattern for all findings but completely different internal schemas

4. **No Clear Separation**: Questions, findings, errors, and metadata all mixed together

## Schema v2.0 Design Principles

### 1. Separation of Concerns
- **Questions**: Dedicated top-level section for investigation questions
- **Findings**: Investigation findings organized by analysis area  
- **Processing**: Agent status and errors separate from data
- **Investigation**: Metadata about the investigation itself

### 2. Consistency
- All findings follow the same base schema
- Questions have a unified structure regardless of how they were generated
- Clear required vs optional fields

### 3. Error Isolation
- Processing errors tracked separately in `processing.errors`
- No more error findings mixed with actual investigation data
- Clear error context and stack traces

### 4. Extensibility
- Schema versioning for migration support
- Easy to add new finding types
- Clear extension points for future features

## Schema Structure

```json
{
  "schema_version": "2.0",
  "investigation": { /* Investigation metadata */ },
  "questions": {
    "summary": { /* Question counts and metadata */ },
    "items": [ /* Array of question objects */ ]
  },
  "findings": {
    "network_analysis": [ /* Findings array */ ],
    "endpoint_behaviors": [ /* Findings array */ ],
    /* etc */
  },
  "processing": {
    "agents": { /* Agent status */ },
    "errors": [ /* Processing errors */ ]
  },
  "risk_scores": { /* Risk assessment */ }
}
```

## Example: Investigation Questions

### Old Format (Problematic)
```json
{
  "knowledge_areas": {
    "investigation_questions": [
      {
        "id": "summary-001",
        "finding": {
          "type": "questions_summary",
          "total_questions": 0
        }
      },
      {
        "id": "error-001", 
        "finding": {
          "type": "tool_mapping_error",
          "error": "'dict' object has no attribute 'finding'"
        }
      },
      {
        "id": "batch-001",
        "finding": {
          "type": "questions_batch",
          "original_questions": [...]
        }
      }
    ]
  }
}
```

### New Format (Clean)
```json
{
  "questions": {
    "summary": {
      "total_count": 3,
      "by_category": {
        "initial_assessment": 1,
        "technical_analysis": 1,
        "impact_assessment": 1
      },
      "by_priority": {
        "critical": 1,
        "high": 2
      },
      "generated_at": "2025-06-21T16:05:00Z"
    },
    "items": [
      {
        "id": "Q001",
        "question": "What specific indicators triggered this security alert?",
        "category": "initial_assessment",
        "priority": "critical",
        "rationale": "Understanding initial detection helps scope investigation",
        "investigation_areas": ["network_analysis", "log_correlation"],
        "expected_evidence_types": ["security_alerts", "logs"],
        "created_at": "2025-06-21T16:05:00Z",
        "created_by": "coordinator",
        "enhancement": {
          "available_tools": [
            {
              "tool_name": "get_security_alerts",
              "tool_category": "siem",
              "relevance": "high",
              "usage_description": "Retrieve triggering alerts"
            }
          ],
          "suggested_approach": "Use get_security_alerts then search_security_events",
          "data_sources_needed": ["SIEM_logs", "network_traffic"]
        }
      }
    ]
  },
  "processing": {
    "agents": {
      "coordinator": {
        "status": "completed",
        "last_run": "2025-06-21T16:05:00Z",
        "findings_generated": 3
      }
    },
    "errors": []
  }
}
```

## Example: Processing Errors

### Old Format (Mixed with Data)
```json
{
  "investigation_questions": [
    {
      "finding": {
        "type": "tool_mapping_error",
        "error": "'dict' object has no attribute 'finding'"
      }
    }
  ]
}
```

### New Format (Isolated)
```json
{
  "processing": {
    "errors": [
      {
        "id": "error-001",
        "timestamp": "2025-06-21T16:05:00Z",
        "agent": "coordinator",
        "operation": "question_enhancement",
        "error_type": "AttributeError",
        "message": "'dict' object has no attribute 'finding'",
        "context": {
          "processing_step": "tool_mapping",
          "input_data_type": "dict"
        }
      }
    ]
  }
}
```

## Findings Structure

All findings follow a consistent schema:

```json
{
  "id": "uuid",
  "timestamp": "2025-06-21T16:05:00Z",
  "agent": "network_analyzer",
  "area": "network_analysis", 
  "type": "dns_suspicious",
  "data": {
    "source_ip": "192.168.1.100",
    "domain": "malicious.example.com",
    "threat_level": "high"
  },
  "confidence": "high",
  "tags": ["dns", "c2_communication", "malware"],
  "metadata": {
    "created_by": "network_analyzer",
    "source": "chronicle_query",
    "evidence_links": ["case-3052-alert-001"]
  }
}
```

## Migration Strategy

### Phase 1: Dual Support
1. Update APIs to accept both v1 and v2 formats
2. Add schema detection and conversion utilities
3. Update web interface to handle both formats

### Phase 2: Data Migration
1. Convert existing blackboard files to v2 format
2. Update coordinator to generate v2 format
3. Validate all agents work with new schema

### Phase 3: Deprecation
1. Remove v1 format support
2. Clean up conversion utilities
3. Update documentation

## Benefits

1. **Clear Question Management**: Questions no longer mixed with errors or metadata
2. **Better Error Handling**: Processing errors tracked separately and systematically
3. **Consistent Processing**: All components know exactly what to expect
4. **Easier UI Development**: Clear data structure makes frontend development simpler
5. **Better Debugging**: Errors and processing status clearly visible
6. **Schema Validation**: Can validate data structure programmatically

## Implementation Requirements

### For Coordinator
- Generate questions in new `questions.items` format
- Store processing errors in `processing.errors`
- Update question enhancement to use new structure

### For Web Interface  
- Update Questions tab to use `questions.items` directly
- Display processing errors from `processing.errors`
- Add schema version detection

### For All Agents
- Update to generate findings in consistent format
- Use new error reporting structure
- Validate output against schema

## Validation

Use the JSON Schema file (`investigation-schema-v2.json`) to validate:

```python
import json
import jsonschema

with open('investigation-schema-v2.json') as f:
    schema = json.load(f)

with open('investigation-data.json') as f:
    data = json.load(f)

jsonschema.validate(data, schema)
```

## Next Steps

1. **Review Schema**: Team review of proposed schema
2. **Prototype Implementation**: Update coordinator to generate v2 format
3. **API Updates**: Modify web interface APIs for dual support
4. **Testing**: Comprehensive testing with real investigation data
5. **Migration**: Convert existing investigations to new format
6. **Deployment**: Roll out schema v2 across all components