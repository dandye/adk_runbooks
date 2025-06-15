#!/usr/bin/env python
"""Simple runner for testing Threat Hunter A2A integration."""

import asyncio
from agent_a2a import ThreatHunterA2A


async def main():
    """Test the Threat Hunter A2A agent."""
    print("=== Threat Hunter A2A Test ===\n")

    # Create the agent
    agent = ThreatHunterA2A()

    # Test queries
    test_queries = [
        "Hunt for signs of lateral movement using psexec.",
        "Proactively hunt for the latest APT campaign.",
        "Search for evidence of living-off-the-land techniques.",
        "Investigate the use of DNS tunneling for C2 communications.",
        "Hunt for anomalous PowerShell execution on critical servers.",
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
