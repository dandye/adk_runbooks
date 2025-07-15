# SOC Blackboard Schema Documentation

This directory contains the improved JSON schema definition and migration tools for SOC investigation blackboard data.

## Files

- **`investigation-schema-v2.json`** - Complete JSON Schema definition for v2.0 format
- **`SCHEMA-DESIGN.md`** - Comprehensive design documentation with examples and migration strategy  
- **`migrate-v1-to-v2.py`** - Python utility to convert existing v1 investigations to v2 format
- **`README.md`** - This file

## Key Improvements in Schema v2.0

### 🔧 **Fixed Data Structure Issues**
- **Questions** now have dedicated, clean structure separate from findings
- **Processing errors** isolated from investigation data  
- **Consistent finding format** across all analysis areas
- **Clear separation** between data, metadata, and processing info

### 🎯 **Addresses Current Problems**
- ✅ Eliminates `"'dict' object has no attribute 'finding'"` errors
- ✅ Questions no longer mixed with errors and summaries
- ✅ Clear, consistent API for web interface  
- ✅ Proper error tracking and debugging support

### 📊 **Better Organization**
```
investigation-data.json
├── schema_version: "2.0"
├── investigation: { id, status, case_context }
├── questions: { summary, items[] }
├── findings: { network_analysis[], ioc_enrichments[], ... }
├── processing: { agents{}, errors[] }
└── risk_scores: { ... }
```

## Quick Start

### Test Migration
```bash
# Validate existing file can be migrated
python schema/migrate-v1-to-v2.py blackboard_data/investigation_SOAR-2025-001234.json --validate-only

# Convert to v2 format
python schema/migrate-v1-to-v2.py input.json output-v2.json --pretty
```

### Schema Validation
```python
import json
import jsonschema

# Load schema
with open('schema/investigation-schema-v2.json') as f:
    schema = json.load(f)

# Validate data
with open('investigation-data.json') as f:
    data = json.load(f)
    
jsonschema.validate(data, schema)  # Throws exception if invalid
```

## Migration Strategy

1. **Phase 1**: Update APIs to support both v1 and v2 formats
2. **Phase 2**: Convert coordinator to generate v2 format  
3. **Phase 3**: Migrate existing investigation files
4. **Phase 4**: Remove v1 compatibility

## Impact on Components

### Web Interface (monitoring_web.py)
- Questions tab can use `questions.items` directly
- No more complex format detection needed
- Clear error display from `processing.errors`

### Coordinator (agent.py)  
- Generate questions in clean `questions.items` format
- Store processing errors in `processing.errors`
- No more confusing finding wrapper for questions

### All Agents
- Consistent finding format: `{id, timestamp, agent, area, type, data, confidence, tags, metadata}`
- Clear error reporting structure
- Schema validation support

## Benefits Summary

| Issue | v1.x Problem | v2.0 Solution |
|-------|-------------|---------------|
| Question Storage | Mixed with errors/summaries | Clean dedicated section |
| Error Handling | Pollutes investigation data | Isolated tracking |
| Schema Consistency | Different formats everywhere | Unified structure |
| UI Development | Complex format detection | Direct data access |
| Debugging | Errors buried in findings | Clear error section |
| Validation | No schema validation | Full JSON Schema support |

## Next Steps

1. **Review** the schema design and documentation
2. **Test** migration utility with your investigation files  
3. **Update** coordinator to generate v2 format
4. **Modify** web interface APIs for dual format support
5. **Deploy** schema v2 across all components

The schema is designed to be backwards compatible during migration and provides a clear path forward for resolving the persistent data structure issues.