#!/bin/bash

# Run script for complete ADK Runbooks container
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="adk-runbooks"
IMAGE_TAG="complete"
CONTAINER_NAME="adk-runbooks-complete"

# Parse command line arguments
MODE="run"  # Default mode
if [ "$1" = "web" ]; then
    MODE="web"
    echo -e "${BLUE}Starting in web mode...${NC}"
fi

echo -e "${GREEN}Running Complete ADK Runbooks container...${NC}"
echo "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo "Container: ${CONTAINER_NAME}"
echo "Mode: ${MODE}"
echo ""

# Check if image exists
if ! podman image exists ${IMAGE_NAME}:${IMAGE_TAG}; then
    echo -e "${YELLOW}Image not found. Building...${NC}"
    ./podman-build-complete.sh
    if [ $? -ne 0 ]; then
        echo -e "${RED}Build failed!${NC}"
        exit 1
    fi
fi

# Check for required environment variables
echo "Checking environment variables..."

# Required for basic operation
if [ -z "$GOOGLE_API_KEY" ]; then
    echo -e "${RED}Error: GOOGLE_API_KEY not set${NC}"
    echo "Please set: export GOOGLE_API_KEY=your_key_here"
    exit 1
else
    echo -e "${GREEN}✓ GOOGLE_API_KEY set${NC}"
fi

# Optional MCP tool configuration
MCP_ENV_VARS=""
if [ -n "$CHRONICLE_PROJECT_ID" ]; then
    echo -e "${GREEN}✓ Chronicle configuration found${NC}"
    MCP_ENV_VARS="${MCP_ENV_VARS} -e CHRONICLE_PROJECT_ID=${CHRONICLE_PROJECT_ID}"
    MCP_ENV_VARS="${MCP_ENV_VARS} -e CHRONICLE_CUSTOMER_ID=${CHRONICLE_CUSTOMER_ID}"
    MCP_ENV_VARS="${MCP_ENV_VARS} -e CHRONICLE_REGION=${CHRONICLE_REGION:-us}"
else
    echo -e "${YELLOW}⚠ No Chronicle configuration (MCP tools may not work)${NC}"
fi

if [ -n "$SOAR_URL" ]; then
    echo -e "${GREEN}✓ SOAR configuration found${NC}"
    MCP_ENV_VARS="${MCP_ENV_VARS} -e SOAR_URL=${SOAR_URL}"
    MCP_ENV_VARS="${MCP_ENV_VARS} -e SOAR_APP_KEY=${SOAR_APP_KEY}"
else
    echo -e "${YELLOW}⚠ No SOAR configuration (MCP tools may not work)${NC}"
fi

# Check for Google Cloud credentials
ADC_PATH="$HOME/.config/gcloud/application_default_credentials.json"
ADC_MOUNT=""
if [ -f "$ADC_PATH" ]; then
    echo -e "${GREEN}✓ Google Cloud credentials found${NC}"
    ADC_MOUNT="-v $ADC_PATH:/root/.config/gcloud/application_default_credentials.json:ro"
else
    echo -e "${YELLOW}⚠ No Google Cloud credentials${NC}"
fi

# Prepare port mapping for web mode
PORT_MAP=""
if [ "$MODE" = "web" ]; then
    PORT_MAP="-p 8501:8501"
    echo ""
    echo "Web UI will be available at: http://localhost:8501"
fi

echo ""
echo -e "${YELLOW}Starting container...${NC}"

# Stop any existing container with same name
podman stop ${CONTAINER_NAME} 2>/dev/null || true
podman rm ${CONTAINER_NAME} 2>/dev/null || true

# Run the container with all configurations
# Mount the .env file as read-write instead of mounting directories as read-only
podman run \
    --rm \
    -it \
    --name ${CONTAINER_NAME} \
    ${PORT_MAP} \
    ${ADC_MOUNT} \
    -e GOOGLE_API_KEY="${GOOGLE_API_KEY}" \
    -e GOOGLE_GENAI_USE_VERTEXAI=False \
    ${MCP_ENV_VARS} \
    -v $(pwd)/multi-agent:/app/multi-agent \
    -v $(pwd)/rules-bank:/app/rules-bank:ro \
    -v $(pwd)/external:/app/external \
    ${IMAGE_NAME}:${IMAGE_TAG} \
    ${MODE}

echo ""
echo -e "${GREEN}Container stopped.${NC}"