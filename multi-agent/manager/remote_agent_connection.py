"""Remote agent connection handler for A2A communication."""

import json
import uuid
import logging
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)


class RemoteAgentConnection:
    """Manages connection and communication with a remote A2A agent."""
    
    def __init__(self, agent_name: str, agent_url: str, agent_card: Dict[str, Any]):
        """
        Initialize remote agent connection.
        
        Args:
            agent_name: Name identifier for the agent
            agent_url: Base URL where the agent is hosted
            agent_card: A2A card containing agent metadata
        """
        self.agent_name = agent_name
        self.agent_url = agent_url
        self.agent_card = agent_card
        self.session_id = str(uuid.uuid4())
        
    async def send_message(self, message: str) -> str:
        """
        Send a message to the remote agent and get response.
        
        Args:
            message: The message to send to the agent
            
        Returns:
            The agent's response as a string
        """
        task_id = str(uuid.uuid4())
        message_id = str(uuid.uuid4())
        
        # Construct the A2A message payload
        payload = {
            "message": message,
            "session_id": self.session_id,
            "task_id": task_id,
            "message_id": message_id,
        }
        
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                # Send message to the agent's endpoint
                response = await client.post(
                    f"{self.agent_url}/message",
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code != 200:
                    logger.error(f"Agent {self.agent_name} returned status {response.status_code}")
                    return f"Error: Agent returned status {response.status_code}"
                
                # Parse the response
                result = response.json()
                
                # Handle different response formats
                if isinstance(result, dict):
                    # Check for content in response
                    if "content" in result:
                        return str(result["content"])
                    elif "response" in result:
                        return str(result["response"])
                    elif "error" in result:
                        return f"Agent error: {result['error']}"
                    else:
                        # Return the entire response as JSON
                        return json.dumps(result, indent=2)
                else:
                    return str(result)
                    
        except httpx.TimeoutException:
            logger.error(f"Timeout communicating with {self.agent_name}")
            return f"Error: Timeout communicating with {self.agent_name}"
        except Exception as e:
            logger.error(f"Error communicating with {self.agent_name}: {e}")
            return f"Error communicating with {self.agent_name}: {str(e)}"
    
    def get_capabilities(self) -> Dict[str, Any]:
        """Get the agent's capabilities from its card."""
        return {
            "name": self.agent_name,
            "description": self.agent_card.get("description", "No description"),
            "instructions": self.agent_card.get("instructions", "No instructions"),
            "tools": self.agent_card.get("tools", []),
        }