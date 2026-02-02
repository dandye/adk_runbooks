# MCP Tools Unit Tests

This directory contains unit tests for the MCP (Model Context Protocol) tools integration.

## Test Files

- `test_mcp_tools.py`: Tests for SOAR MCP toolset initialization and basic functionality

## Running Tests

### Prerequisites

1. Set up environment variables in `external/mcp-security/.env`:
   ```bash
   SOAR_APP_KEY=your-app-key
   SOAR_URL=your-soar-url
   CHRONICLE_PROJECT_ID=your-project-id
   CHRONICLE_CUSTOMER_ID=your-customer-id
   CHRONICLE_REGION=us
   VT_APIKEY=your-virustotal-api-key
   ```

2. Ensure the MCP security submodule is initialized:
   ```bash
   git submodule update --init --recursive
   ```

3. Install test dependencies:
   ```bash
   pip install pytest pytest-asyncio
   ```

### Running All Tests

From the `multi-agent` directory:
```bash
pytest tests/
```

Or with verbose output:
```bash
pytest tests/ -v -s
```

### Running Specific Tests

```bash
# Run only SOAR tests
pytest tests/test_mcp_tools.py -v

# Run a specific test function
pytest tests/test_mcp_tools.py::test_soar_list_cases -v
```

## Test Cases

### test_soar_list_cases

This test implements three test cases as requested:

1. **Test Case 1**: SOAR toolset initialization - Verifies the toolset can be created
2. **Test Case 2**: Connection parameters configuration - Ensures parameters are set correctly
3. **Test Case 3**: Tool name prefix validation - Confirms the prefix is set to "soar-mcp"

### Security Considerations

The tests are designed to:
- Use environment variables for credentials (never hardcoded)
- NOT print sensitive data (API keys, secrets, or case data)
- Skip tests if required environment variables are not set
- Provide clear pass/fail status without exposing sensitive information

## Notes

- Tests use the actual MCP toolset initialization but do not make live API calls that would return sensitive data
- The tests validate configuration and initialization, ensuring the tools are ready to use
- Sensitive API responses are intentionally not displayed in test output
