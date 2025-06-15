#!/usr/bin/env python
"""Simple runner for testing SOC Analyst Tier 3 A2A integration."""

import asyncio
from agent_a2a import SOCAnalystTier3A2A


async def main():
    """Test the SOC Analyst Tier 3 A2A agent."""
    print("=== SOC Analyst Tier 3 A2A Test ===\n")

    # Create the agent
    agent = SOCAnalystTier3A2A()

    # Test queries
    test_queries = [
        "Perform a deep dive investigation into the malware alert on WS-001.",
        "Analyze the suspicious login from 192.168.1.100 and determine the root cause.",
        "Investigate the phishing email and identify the extent of the data exfiltration.",
        "Conduct a forensic analysis of the domain controller after the brute force attack.",
        "Hunt for lateral movement following the anomalous network activity.",
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
