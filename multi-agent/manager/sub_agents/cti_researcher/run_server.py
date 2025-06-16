#!/usr/bin/env python
"""Run CTI Researcher A2A agent as a standalone server."""

import sys
import os
# Add the multi-agent directory to the path to import modules properly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

import asyncio
import json
import logging
from typing import Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from manager.sub_agents.cti_researcher.agent_a2a import CTIResearcherA2A

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(title="CTI Researcher A2A Agent")

# Initialize the agent
agent = CTIResearcherA2A()


class MessageRequest(BaseModel):
    message: str
    session_id: str
    task_id: str
    message_id: str


@app.get("/")
async def root():
    """Root endpoint returning agent card."""
    return {
        "name": "cti_researcher",
        "description": "CTI Researcher specializing in threat intelligence analysis",
        "instructions": "Send threat intelligence research requests",
        "tools": ["create_research_request_form", "return_research_form", "start_research"],
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
    logger.info("Shutting down CTI Researcher agent...")
    await agent.cleanup()


if __name__ == "__main__":
    # Run the server
    uvicorn.run(app, host="0.0.0.0", port=8001)