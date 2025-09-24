#!/bin/bash

# Build script for complete ADK Runbooks container
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="adk-runbooks"
IMAGE_TAG="complete"
DOCKERFILE="Dockerfile.adk-complete"
PLATFORM="linux/amd64"

echo -e "${GREEN}Building Complete ADK Runbooks container...${NC}"
echo "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo "Dockerfile: ${DOCKERFILE}"
echo "Platform: ${PLATFORM}"
echo "This build includes:"
echo "  - uv package manager for MCP tools"
echo "  - Fixed typos in agent code"
echo "  - Proper directory symlinks"
echo "  - MCP dependencies"
echo ""

# Check if Dockerfile exists
if [ ! -f "${DOCKERFILE}" ]; then
    echo -e "${RED}Error: ${DOCKERFILE} not found!${NC}"
    exit 1
fi

# Build the container
echo -e "${YELLOW}Starting build (this may take a few minutes)...${NC}"
podman build --platform ${PLATFORM} -t ${IMAGE_NAME}:${IMAGE_TAG} -f ${DOCKERFILE} .

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ Build completed successfully!${NC}"
    echo ""
    echo "To run the container:"
    echo "  ./podman-run-complete.sh"
else
    echo -e "${RED}✗ Build failed!${NC}"
    exit 1
fi