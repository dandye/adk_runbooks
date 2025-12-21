import time
import functools
import logging
import json
import os
from datetime import datetime

# Configure logging for instrumentation
logger = logging.getLogger("tool_instrumentation")
logger.setLevel(logging.INFO)

# Metrics storage
# NOTE: RUN_METRICS is a global list that accumulates metrics across multiple
# executions within the same process lifetime. For production use, consider:
# (1) resetting RUN_METRICS at the start of each execution,
# (2) scoping metrics to individual execution sessions with unique identifiers, or
# (3) using a class-based approach where each execution gets its own metrics instance.
RUN_METRICS = []

def estimate_tokens(text: str) -> int:
    """Rough token estimation using ~4 characters per token.

    Note:
        This is a coarse heuristic and can be significantly inaccurate for
        some content types (e.g., code, JSON, or other structured data).
        For precise token counts, use a tokenizer provided by your LLM
        provider (e.g., tiktoken for OpenAI models).
    """
    if not text:
        return 0
    return len(str(text)) // 4

def instrument_tool(tool_func):
    """Wraps a tool with metrics collection using a function-based decorator
    to preserve the function signature for ADK inspection.
    
    WARNING: This instrumentation logs tool arguments and results, which may
    contain sensitive data (passwords, API keys, PII). Ensure execution_metrics.jsonl
    has appropriate access controls and consider sanitizing sensitive data or
    excluding certain tools from instrumentation for production use.
    """
    @functools.wraps(tool_func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        start_dt = datetime.now()
        status = "success"
        result = None

        try:
            result = tool_func(*args, **kwargs)
            return result
        except Exception as e:
            status = "error"
            result = str(e)
            raise e
        finally:
            end_time = time.time()
            duration = end_time - start_time

            # Estimate tokens
            input_str = str(args) + str(kwargs)
            output_str = str(result)
            tokens_in = estimate_tokens(input_str)
            tokens_out = estimate_tokens(output_str)

            metric = {
                "timestamp": start_dt.isoformat(),
                "tool_name": tool_func.__name__,
                "duration_seconds": round(duration, 4),
                "status": status,
                "estimated_tokens_in": tokens_in,
                "estimated_tokens_out": tokens_out,
                "total_estimated_tokens": tokens_in + tokens_out
            }

            RUN_METRICS.append(metric)

            # Log to file (append mode)
            try:
                log_dir = os.path.join(os.path.dirname(__file__), "..", "..", "reports")
                os.makedirs(log_dir, exist_ok=True)
                log_file = os.path.join(log_dir, "execution_metrics.jsonl")
                with open(log_file, "a") as f:
                    f.write(json.dumps(metric) + "\n")
            except Exception as log_err:
                logger.error(f"Failed to log metric: {log_err}")

    return wrapper

def get_run_metrics() -> str:
    """Returns a summary of the execution metrics collected so far.

    Returns:
        str: JSON string of collected metrics.
    """
    return json.dumps(RUN_METRICS, indent=2)
