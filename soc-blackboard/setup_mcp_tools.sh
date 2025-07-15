#!/bin/bash
# Setup script for SOC Blackboard MCP Security Tools

set -e

echo "Setting up SOC Blackboard MCP Security Tools..."
echo "================================================"

# Check if we're in the correct directory
if [ ! -f "requirements.txt" ] || [ ! -d "../external/mcp-security" ]; then
    echo "Error: Please run this script from the soc-blackboard directory"
    echo "Expected structure:"
    echo "  adk_runbooks/"
    echo "    ├── soc-blackboard/  ← Run script from here"
    echo "    └── external/"
    echo "        └── mcp-security/"
    exit 1
fi

echo "1. Installing SOC Blackboard requirements..."
pip install -r requirements.txt

echo "2. Installing MCP Security Tools..."

# Install Google Security Operations (Chronicle) tools
echo "  - Installing Google Security Operations (Chronicle) tools..."
pip install -e ../external/mcp-security/server/secops

# Install Google Threat Intelligence tools  
echo "  - Installing Google Threat Intelligence tools..."
pip install -e ../external/mcp-security/server/gti

# Install SOAR tools
echo "  - Installing SOAR tools..."
pip install -e ../external/mcp-security/server/secops-soar

# Install Security Command Center tools
echo "  - Installing Security Command Center tools..."
pip install -e ../external/mcp-security/server/scc

echo "3. Verifying installation..."
python -c "
try:
    import secops_mcp
    import gti_mcp
    import secops_soar_mcp
    import scc_mcp
    print('✓ All MCP security tools imported successfully')
except ImportError as e:
    print(f'⚠ Warning: Some tools may not be available: {e}')
    print('This is normal if you haven\'t configured authentication yet')
"

echo ""
echo "Setup complete! 🎉"
echo ""
echo "Next steps:"
echo "1. Copy .env.example to .env and configure your credentials:"
echo "   cp .env.example .env"
echo "   # Edit .env with your Google Cloud project and API keys"
echo ""
echo "2. Set up Google Cloud authentication:"
echo "   gcloud auth application-default login"
echo ""
echo "3. Run the SOC Blackboard system:"
echo "   adk run coordinator  # or adk web"
echo ""
echo "For more information, see README.md"