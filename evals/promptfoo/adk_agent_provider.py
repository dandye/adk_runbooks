"""Custom Promptfoo Provider for ADK Multi-Agent Evaluation."""

import asyncio
from typing import Any, Dict

# ADK agent wrapper function for Promptfoo custom python provider
async def call_api(prompt: str, options: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Execute ADK agent and return formatted output for Promptfoo assertions."""
    vars_dict = context.get("vars", {})
    user_input = vars_dict.get("user_query") or prompt

    try:
        # Import ADK multi-agent manager if present
        from manager.agent import root_agent

        response = await root_agent.run_async(user_input)
        output_text = getattr(response, "text", str(response))
        metrics = getattr(response, "metrics", None)

        return {
            "output": output_text,
            "tokenUsage": {
                "total": getattr(metrics, "total_tokens", 0) if metrics else 0,
                "prompt": getattr(metrics, "prompt_tokens", 0) if metrics else 0,
                "completion": getattr(metrics, "completion_tokens", 0) if metrics else 0,
            },
            "cost": 0.0,
        }
    except Exception as e:
        return {"error": f"ADK agent execution error: {str(e)}"}


def call_api_sync(prompt: str, options: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Synchronous interface called by Promptfoo."""
    return asyncio.run(call_api(prompt, options, context))
