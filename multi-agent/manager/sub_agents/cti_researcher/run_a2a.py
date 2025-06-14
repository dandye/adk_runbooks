#!/usr/bin/env python
"""Simple runner for testing CTI Researcher A2A integration."""

import asyncio
from agent_a2a import CTIResearcherA2A


async def main():
    """Test the CTI Researcher A2A agent."""
    print("=== CTI Researcher A2A Test ===\n")
    
    # Create the agent
    agent = CTIResearcherA2A()
    
    # Test queries
    test_queries = [
        "I need to research a new APT campaign targeting financial institutions",
        "Investigate IOCs: 192.168.1.1, malware.exe, evil.com",
        "Research threat actor Lazarus Group activities in the last 30 days",
        "Analyze GTI collection ID GTI-2024-001 with high priority",
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