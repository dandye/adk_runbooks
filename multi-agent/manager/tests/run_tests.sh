#!/bin/bash

# Script to run all configuration system tests

echo "🧪 Running Agent Configuration System Tests"
echo "=========================================="

# Set Python path
export PYTHONPATH="${PYTHONPATH}:$(dirname $(dirname $(realpath $0)))"

echo -e "\n1️⃣  Validating Configuration Files..."
echo "--------------------------------------"
python3 validate_configs.py
VALIDATE_EXIT=$?

echo -e "\n2️⃣  Running Unit Tests..."
echo "--------------------------------------"
python3 test_config_system.py
TEST_EXIT=$?

echo -e "\n3️⃣  Running Delegation Demo..."
echo "--------------------------------------"
# Run non-interactive demo
python3 -c "
import sys
sys.path.append('..')
from config.config_loader import load_agent_config

config_loader = load_agent_config()
print('Testing sample delegations:\n')

test_cases = [
    'Triage security alert',
    'Investigate SOAR case',
    'Analyze malware sample',
    'Research threat actors',
    'Create detection rule'
]

for request in test_cases:
    agent = config_loader.get_agent_for_request(request)
    if agent:
        config = config_loader.get_agent_capabilities(agent)
        print(f\"'{request}' → {config.get('display_name', agent)}\")
    else:
        print(f\"'{request}' → No match\")
"

echo -e "\n✅ Test Summary"
echo "==============="
echo "Validation: $([ $VALIDATE_EXIT -eq 0 ] && echo 'PASSED' || echo 'FAILED')"
echo "Unit Tests: $([ $TEST_EXIT -eq 0 ] && echo 'PASSED' || echo 'FAILED')"

# Overall exit code
[ $VALIDATE_EXIT -eq 0 ] && [ $TEST_EXIT -eq 0 ]