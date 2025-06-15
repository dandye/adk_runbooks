#!/usr/bin/env python
"""Simple runner for testing Incident Responder A2A integration."""

import asyncio
from agent_a2a import IncidentResponderA2A


async def main():
    """Test the Incident Responder A2A agent."""
    print("=== Incident Responder A2A Test ===\n")

    # Create the agent
    agent = IncidentResponderA2A()

    # Test queries
    test_queries = [
        "Contain the host WS-001 due to a malware infection.",
        "Isolate the user account 'admin' due to a suspected compromise.",
        "Block the IP address 192.168.1.100 at the firewall.",
        "Eradicate the malware from the infected host.",
        "Begin the recovery process for the compromised system.",
    ]

    for i, query in enumerate(test_queries):
        print(f"\nTest {i+1}: {query}")
        print("-" * 50)

        session_id = f"test_session_{i}"

        # Stream the response
        async for update in agent.stream(query, session_id):
            if update['is_task_complete']:
                print(f"Response: {update['content']}")
            else:
                print(f"Status: {update['updates']}")

        print("\n" + "="*50)

        # Wait a bit between tests
        await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
