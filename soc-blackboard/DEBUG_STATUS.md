# SOC Blackboard Debugging Status

## Date: December 20, 2024

### Current Issue
The SOC Blackboard coordinator is experiencing issues with agent invocation. The main problems encountered:

1. **Initial Error**: Agent hallucination trying to call non-existent `run_code` function
   - **Fixed**: Added explicit tool constraints to agent instructions

2. **Second Error**: `'str' object has no attribute 'model_copy'` when using `run_async` with string
   - **Fixed**: Switched from passing raw strings to using proper ADK patterns

3. **Third Error**: `ModuleNotFoundError: No module named 'google.adk.invocation_context'`
   - **Fixed**: Corrected import path to `google.adk.agents.invocation_context`

4. **Fourth Error**: ValidationError when creating InvocationContext manually
   - **Fixed**: Switched to using Runner API instead of manual InvocationContext creation

5. **Fifth Error**: `'coroutine' object has no attribute 'id'` on session creation
   - **Fixed**: Added `await` to async `create_session` calls

6. **Sixth Error**: `ValueError: Default value None of parameter area: str = None`
   - **Fixed**: Changed default to empty string for `blackboard_read`

7. **Seventh Error**: `ValueError: Default value None of parameter tags: list = None`
   - **Fixed**: Used `Optional[List[str]]` type annotation for `blackboard_write`

8. **Current Error**: `400 INVALID_ARGUMENT ... tags.items: missing field`
   - **Fixed**: Changed `list` to `List[str]` to properly define list item type
   - **Status**: Need to test if this resolves the API schema validation issue

### What Was Changed
1. Added explicit tool constraints to prevent `run_code` hallucinations
2. Replaced manual string-based agent invocation with ADK Runner API
3. Updated all three agent invocation points:
   - Investigator agents in `_run_investigator`
   - Correlation engine in `_run_correlation_analysis`
   - Report generator in `_generate_report`

### Next Steps
1. Test if the `await` fix resolves the session creation issue
2. If not, investigate alternative invocation patterns (possibly using the simpler patterns from DAC agent)
3. Consider implementing a wrapper method to standardize agent invocation across the coordinator
4. Add proper error handling and logging for agent responses
5. Verify that agent responses are properly captured and written to the blackboard

### Notes
- The ADK `Agent` class doesn't have a `process_request` method by default
- The Runner API is the recommended way to invoke agents programmatically
- InvocationContext should not be manually created - it's handled by the framework
- Session services may require async initialization

### Testing Environment and Command
We are testing the soc-blackboard with the following setup:
```bash
❯ pwd
/Users/dandye/Projects/adk_runbooks/soc-blackboard
❯ echo $VIRTUAL_ENV
/Users/dandye/Projects/adk_runbooks/soc-blackboard/venv
❯ which adk
/Users/dandye/homebrew/Caskroom/miniconda/base/bin/adk
❯ adk --version
adk, version 1.3.0
```

Test command:
```bash
echo "start an investigation for soar case 3052" | adk run coordinator | tee out.log
```