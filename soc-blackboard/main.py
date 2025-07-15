#!/usr/bin/env python3
"""
SOC Blackboard Main Entry Point

Run the SOC Blackboard system for collaborative security investigations.
"""

import asyncio
import os
from pathlib import Path
from dotenv import load_dotenv

from coordinator import get_agent


async def main():
    """Main entry point for SOC Blackboard system."""
    
    # Load environment variables
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
    
    # Check for required environment variables
    required_vars = ["GOOGLE_API_KEY"]
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
        print("Please set these in your .env file or environment.")
        return 1
    
    print("SOC Blackboard System")
    print("====================")
    print()
    print("A collaborative security investigation platform using the Blackboard pattern.")
    print("Multiple specialized agents work together through a shared knowledge store.")
    print()
    
    # For now, just show system info since we need to integrate with ADK properly
    print("System Components:")
    print("- Coordinator: Orchestrates investigation workflow")
    print("- Investigators: Network, Endpoint, Log, IOC, Timeline specialists")
    print("- Synthesizers: Correlation Engine, Report Generator")
    print("- Blackboard: Shared knowledge store for agent collaboration")
    print()
    
    print("To run with ADK:")
    print("1. Ensure you're in a Python environment with ADK installed")
    print("2. Configure your .env file with API keys")
    print("3. Run: adk run coordinator")
    print("   OR")
    print("4. Run: adk web")
    print()
    
    print("Configuration files:")
    print(f"- .env: {env_path}")
    print(f"- Requirements: {Path(__file__).parent / 'requirements.txt'}")
    print()
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    exit(exit_code)