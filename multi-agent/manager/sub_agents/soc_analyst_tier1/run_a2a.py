#!/usr/bin/env python
"""Simple runner for testing SOC Analyst Tier 1 A2A integration."""

import asyncio
from agent_a2a import SOCAnalystTier1A2A


async def main():
    """Test the SOC Analyst Tier 1 A2A agent."""
    print("=== SOC Analyst Tier 1 A2A Test ===\n")
    
    # Create the agent
    agent = SOCAnalystTier1A2A()
    
    # Test queries
    test_queries = [
        "I have a high severity malware alert from CrowdStrike affecting user workstation WS-001",
        "Suspicious login detected from IP 192.168.1.100 to admin account",
        "Critical phishing email alert from Splunk with potential data exfiltration",
        "Alert ID ALT-2024-001: Brute force attack detected on domain controller",
        "Anomalous network activity involving multiple internal systems",
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