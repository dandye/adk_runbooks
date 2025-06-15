#!/bin/bash
# Start the A2A multi-agent system

echo "Starting A2A Multi-Agent Security System..."
echo "========================================="

# Function to cleanup on exit
cleanup() {
    echo -e "\n\nShutting down agents..."
    if [ ! -z "$CTI_PID" ]; then
        kill $CTI_PID 2>/dev/null
    fi
    if [ ! -z "$SOC_T1_PID" ]; then
        kill $SOC_T1_PID 2>/dev/null
    fi
    if [ ! -z "$SOC_T2_PID" ]; then
        kill $SOC_T2_PID 2>/dev/null
    fi
    if [ ! -z "$SOAR_PID" ]; then
        kill $SOAR_PID 2>/dev/null
    fi
    exit 0
}

# Set trap for cleanup
trap cleanup EXIT INT TERM

# Check if we're in the multi-agent directory
if [ ! -f "requirements.txt" ]; then
    echo "Error: Please run this script from the multi-agent directory"
    exit 1
fi

# Export environment variables if .env exists
# Check multiple locations for .env file
if [ -f ".env" ]; then
    export $(grep -v '^#' .env | xargs)
elif [ -f "manager/.env" ]; then
    export $(grep -v '^#' manager/.env | xargs)
fi

# Start CTI Researcher agent
echo "Starting CTI Researcher agent on port 8001..."
cd manager/sub_agents/cti_researcher
python run_server.py > cti_agent.log 2>&1 &
CTI_PID=$!
cd ../../..

# Give it time to start and check if it's running
sleep 2
if ! kill -0 $CTI_PID 2>/dev/null; then
    echo "❌ Failed to start CTI Researcher agent. Check cti_agent.log for details."
    exit 1
fi

# Start SOC Analyst Tier 1 agent
echo "Starting SOC Analyst Tier 1 agent on port 8002..."
cd manager/sub_agents/soc_analyst_tier1
python run_server.py > soc_agent.log 2>&1 &
SOC_T1_PID=$!
cd ../../..

# Give it time to start and check if it's running
sleep 2
if ! kill -0 $SOC_T1_PID 2>/dev/null; then
    echo "❌ Failed to start SOC Analyst Tier 1 agent. Check soc_agent.log for details."
    exit 1
fi

# Start SOC Analyst Tier 2 agent
echo "Starting SOC Analyst Tier 2 agent on port 8004..."
cd manager/sub_agents/soc_analyst_tier2
python run_server.py > soc_agent.log 2>&1 &
SOC_T2_PID=$!
cd ../../..

# Give it time to start and check if it's running
sleep 2
if ! kill -0 $SOC_T2_PID 2>/dev/null; then
    echo "❌ Failed to start SOC Analyst Tier 2 agent. Check soc_agent.log for details."
    exit 1
fi

# Start SOAR Specialist agent
echo "Starting SOAR Specialist agent on port 8003..."
cd manager/sub_agents/soar_specialist
python run_server.py > soar_agent.log 2>&1 &
SOAR_PID=$!
cd ../../..

# Give agents time to fully start and check if running
sleep 3
if ! kill -0 $SOAR_PID 2>/dev/null; then
    echo "❌ Failed to start SOAR Specialist agent. Check soar_agent.log for details."
    exit 1
fi

echo -e "\n✅ All agents started successfully!"
echo -e "\nAgent Status:"
echo "- CTI Researcher: http://localhost:8001"
echo "- SOC Analyst Tier 1: http://localhost:8002"
echo "- SOC Analyst Tier 2: http://localhost:8004"
echo "- SOAR Specialist: http://localhost:8003"

echo -e "\nTo start the SOC Manager host agent, run from the multi-agent directory:"
echo "  adk web agents/"
echo "  Then select 'soc_manager_host' from the web interface"

echo -e "\nLogs are available at:"
echo "- manager/sub_agents/cti_researcher/cti_agent.log"
echo "- manager/sub_agents/soc_analyst_tier1/soc_agent.log"
echo "- manager/sub_agents/soc_analyst_tier2/soc_agent.log"
echo "- manager/sub_agents/soar_specialist/soar_agent.log"

echo -e "\nPress Ctrl+C to stop all agents...\n"

# Wait indefinitely
wait
