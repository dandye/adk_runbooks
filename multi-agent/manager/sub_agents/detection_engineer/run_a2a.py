#!/usr/bin/env python
"""Simple runner for testing Detection Engineer A2A integration."""

import asyncio
from agent_a2a import DetectionEngineerA2A


async def main():
    """Test the Detection Engineer A2A agent."""
    print("=== Detection Engineer A2A Test ===\n")

    # Create the agent
    agent = DetectionEngineerA2A()

    # Test queries
    test_queries = [
        "Create a new detection rule for suspicious PowerShell execution.",
        "Tune the existing detection rule for anomalous network activity to reduce false positives.",
        "Write a new rule to detect the use of psexec for lateral movement.",
        "Validate the effectiveness of the new phishing detection rule.",
        "Develop a detection for the latest malware campaign.",
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
