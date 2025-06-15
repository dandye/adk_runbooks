#!/usr/bin/env python
"""Test A2A connection and communication."""

import asyncio
import httpx
import json

async def test_a2a_connection():
    """Test basic connection to A2A agents."""
    
    agents = {
        "cti_researcher": "http://localhost:8001",
        "soc_analyst_tier1": "http://localhost:8002",
    }
    
    for agent_name, agent_url in agents.items():
        print(f"\n=== Testing {agent_name} ===")
        
        try:
            async with httpx.AsyncClient() as client:
                # Test 1: Check if agent is running
                print(f"1. Testing connection to {agent_url}...")
                response = await client.get(agent_url)
                if response.status_code == 200:
                    print(f"   ✅ Agent is running!")
                    print(f"   Card: {json.dumps(response.json(), indent=2)}")
                else:
                    print(f"   ❌ Agent returned status {response.status_code}")
                    continue
                
                # Test 2: Send a simple message
                print(f"\n2. Sending test message...")
                payload = {
                    "message": "Hello, can you help me research APT threats?",
                    "session_id": "test-session-123",
                    "task_id": "test-task-456",
                    "message_id": "test-msg-789"
                }
                
                response = await client.post(
                    f"{agent_url}/message",
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    print(f"   ✅ Message processed successfully!")
                    result = response.json()
                    print(f"   Response: {json.dumps(result, indent=2)}")
                else:
                    print(f"   ❌ Error: Status {response.status_code}")
                    print(f"   Body: {response.text}")
                    
        except Exception as e:
            print(f"   ❌ Connection error: {str(e)}")

if __name__ == "__main__":
    asyncio.run(test_a2a_connection())