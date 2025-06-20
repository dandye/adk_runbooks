#!/usr/bin/env python3
"""
Run script for the Detection-as-Code (DAC) Agent

This script initializes and runs the DAC agent for autonomous rule tuning
based on SOAR case feedback.
"""

import asyncio
import logging
import sys
from pathlib import Path

# Add the parent directory to the path so we can import the agent
sys.path.insert(0, str(Path(__file__).parent))

try:
    from agent import get_root_agent
    from workflow import DACWorkflowExecutor
except ImportError:
    # Handle relative imports when run as script
    import importlib.util
    import os
    
    # Load agent module
    agent_path = os.path.join(os.path.dirname(__file__), 'agent.py')
    spec = importlib.util.spec_from_file_location("agent", agent_path)
    agent_module = importlib.util.module_from_spec(spec)
    
    # Load tools first
    tools_path = os.path.join(os.path.dirname(__file__), 'tools', 'tools.py')
    tools_spec = importlib.util.spec_from_file_location("tools", tools_path)
    tools_module = importlib.util.module_from_spec(tools_spec)
    tools_spec.loader.exec_module(tools_module)
    
    # Add tools to agent module namespace
    agent_module.tools = tools_module
    spec.loader.exec_module(agent_module)
    
    get_root_agent = agent_module.get_root_agent
    
    # Load workflow module
    workflow_path = os.path.join(os.path.dirname(__file__), 'workflow.py')
    workflow_spec = importlib.util.spec_from_file_location("workflow", workflow_path)
    workflow_module = importlib.util.module_from_spec(workflow_spec)
    workflow_spec.loader.exec_module(workflow_module)
    
    DACWorkflowExecutor = workflow_module.DACWorkflowExecutor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dac-agent.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


async def run_autonomous_workflow():
    """Run the DAC agent in autonomous mode."""
    logger.info("Starting DAC Agent in autonomous mode")
    
    try:
        # Initialize the agent
        agent = await get_root_agent()
        logger.info("DAC Agent initialized successfully")
        
        # Get the agent's tools for the workflow executor
        if hasattr(agent, 'tools') and agent.tools:
            workflow_executor = DACWorkflowExecutor(agent.tools)
            
            # Execute the full workflow
            results = await workflow_executor.execute_full_workflow()
            
            # Log results
            logger.info(f"Workflow completed: {results}")
            print(f"\nWorkflow Results:")
            print(f"- Cases found: {results.get('cases_found', 0)}")
            print(f"- Cases processed: {results.get('cases_processed', 0)}")
            print(f"- Rules tuned: {results.get('rules_tuned', 0)}")
            print(f"- PRs created: {results.get('prs_created', 0)}")
            
            if results.get('errors'):
                print(f"- Errors: {len(results['errors'])}")
                for error in results['errors']:
                    print(f"  - {error}")
        else:
            logger.error("Agent tools not available")
            
    except Exception as e:
        logger.error(f"Failed to run DAC Agent: {e}")
        raise


async def run_interactive_mode():
    """Run the DAC agent in interactive mode for testing."""
    logger.info("Starting DAC Agent in interactive mode")
    
    try:
        agent = await get_root_agent()
        logger.info("DAC Agent initialized successfully")
        
        # Interactive prompt
        while True:
            user_input = input("\nEnter a command for the DAC Agent (or 'quit' to exit): ")
            
            if user_input.lower() in ['quit', 'exit', 'q']:
                break
            
            if user_input.lower() in ['workflow', 'run', 'execute']:
                print("Running autonomous workflow...")
                await run_autonomous_workflow()
                continue
            
            # Process the user request
            try:
                response = await agent.process_request(user_input)
                print(f"\nAgent Response:\n{response}")
            except Exception as e:
                logger.error(f"Error processing request: {e}")
                print(f"Error: {e}")
    
    except Exception as e:
        logger.error(f"Failed to run DAC Agent interactively: {e}")
        raise


def main():
    """Main entry point for the DAC agent."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Detection-as-Code Agent")
    parser.add_argument(
        '--mode', 
        choices=['autonomous', 'interactive'], 
        default='autonomous',
        help='Run mode for the DAC agent'
    )
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level'
    )
    
    args = parser.parse_args()
    
    # Set logging level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Run the appropriate mode
    if args.mode == 'autonomous':
        asyncio.run(run_autonomous_workflow())
    else:
        asyncio.run(run_interactive_mode())


if __name__ == "__main__":
    main()