#!/usr/bin/env python
"""Run SOAR Specialist A2A agent as a standalone server."""

import sys
import os
# Add the parent directory to the path to import the agent module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import asyncio
import json
import logging
import signal
from typing import Dict, Any

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from agent_a2a import SOARSpecialistA2A

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(title="SOAR Specialist A2A Agent")

# Initialize the agent
agent = SOARSpecialistA2A()


# Cleanup handler
async def cleanup():
    """Clean up resources on shutdown."""
    logger.info("Cleaning up SOAR agent resources...")
    await agent.cleanup()
    

@app.on_event("shutdown")
async def shutdown_event():
    """Handle shutdown event."""
    await cleanup()


class MessageRequest(BaseModel):
    message: str
    session_id: str
    task_id: str
    message_id: str


@app.get("/")
async def root():
    """Root endpoint returning agent card."""
    return {
        "name": "soar_specialist",
        "description": "SOAR Specialist responsible for case management and orchestration",
        "instructions": "Send SOAR platform queries, case management requests, and workflow operations",
        "tools": ["secops_soar_list_cases", "get_case_full_details", "create_case_management_form", "return_case_form", "create_case"],
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


if __name__ == "__main__":
    # Run the server
    uvicorn.run(app, host="0.0.0.0", port=8003)