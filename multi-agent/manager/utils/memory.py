from google.adk.agents.callback_context import CallbackContext
import logging

async def auto_save_session_to_memory_callback(callback_context: CallbackContext):
    """
    Callback to automatically save the session to the memory bank after agent execution.
    It retrieves the session and memory service from the context and saves the session.
    """
    ctx = callback_context._invocation_context
    if ctx.memory_service:
        try:
            await ctx.memory_service.add_session_to_memory(ctx.session)
            # Log at info level so we can see it working, or debug to be less noisy
            logging.info(f"Session {ctx.session.id} saved to memory bank.")
        except Exception as e:
            logging.error(f"Failed to save session {ctx.session.id} to memory bank: {e}")
    else:
        # This might happen if memory service is not configured, which is fine if intentional.
        # Use debug to avoid spamming if it's not configured.
        logging.debug("Memory service not initialized; skipping session save to memory.")
