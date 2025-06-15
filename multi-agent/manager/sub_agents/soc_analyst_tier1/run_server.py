#!/usr/bin/env python
"""Run SOC Analyst Tier 1 A2A agent as a standalone server."""

import sys
import os
# Add the parent directory to the path to import the agent module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import asyncio
import json
import logging
from typing import Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from agent_a2a import SOCAnalystTier1A2A

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(title="SOC Analyst Tier 1 A2A Agent")

# Initialize the agent
agent = SOCAnalystTier1A2A()


class MessageRequest(BaseModel):
    message: str
    session_id: str
    task_id: str
    message_id: str


@app.get("/")
async def root():
    """Root endpoint returning agent card."""
    return {
        "name": "soc_analyst_tier1",
        "description": "SOC Tier 1 Analyst specializing in alert triage and initial investigation",
        "instructions": "Send security alerts for initial triage and analysis",
        "tools": ["create_alert_triage_form", "return_alert_form", "start_triage"],
        "version": "1.0.0"
    }


@app.post("/message")
async def handle_message(request: MessageRequest) -> Dict[str, Any]:
    """Handle incoming A2A messages."""
    try:
        logger.info(f"Received message: {request.message}")
        
        # Stream responses from the agent
        final_response = ""
        async for update in agent.stream(request.message, request.session_id):
            if update['is_task_complete']:
                final_response = update['content']
            else:
                logger.info(f"Processing: {update['updates']}")
        
        return {
            "task_id": request.task_id,
            "message_id": request.message_id,
            "content": final_response,
            "status": "completed"
        }
        
    except Exception as e:
        logger.error(f"Error processing message: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up resources on shutdown."""
    logger.info("Shutting down SOC Analyst Tier 1 agent...")
    await agent.cleanup()


if __name__ == "__main__":
    # Run the server
    uvicorn.run(app, host="0.0.0.0", port=8002)