#!/bin/bash
# Example script to run MCP tools tests with environment variables
#
# Usage:
#   1. Copy this script: cp run_tests.example.sh run_tests.sh
#   2. Edit run_tests.sh with your actual credentials
#   3. Run: ./run_tests.sh
#
# Note: Make sure run_tests.sh is in .gitignore to avoid committing secrets!

# Set required environment variables for SOAR
export SOAR_APP_KEY="your-app-key-here"
export SOAR_URL="https://your-soar-instance.siemplify-soar.com"

# Set optional environment variables for Chronicle
export CHRONICLE_PROJECT_ID="your-project-id"
export CHRONICLE_CUSTOMER_ID="your-customer-id"
export CHRONICLE_REGION="us"

# Set optional environment variables for VirusTotal
export VT_APIKEY="your-virustotal-api-key"

# Run the tests
echo "Running MCP tools tests..."
pytest tests/test_mcp_tools.py -v -s

# Clean up (optional - remove exports)
unset SOAR_APP_KEY
unset SOAR_URL
unset CHRONICLE_PROJECT_ID
unset CHRONICLE_CUSTOMER_ID
unset CHRONICLE_REGION
unset VT_APIKEY
