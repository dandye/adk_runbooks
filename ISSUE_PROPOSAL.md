# Issue: Explore adding Vertex AI Agent Evaluations for select runbooks

## Description
This issue proposes exploring the integration of [Vertex AI Agent Evaluations](https://docs.cloud.google.com/vertex-ai/generative-ai/docs/models/evaluation-agents) to enhance the testing and quality assurance of our ADK runbooks.

Currently, we have an `llm_judge` agent that manually evaluates runbooks based on rubrics. Vertex AI Agent Evaluations offers a more structured and automated approach, specifically "Trajectory Evaluation," which can programmatically compare the sequence of tool calls made by an agent against a reference trajectory.

## Goals
1.  **Trajectory Evaluation:** Implement automated checks to ensure agents are calling the expected sequence of tools (Exact Match, In-Order Match, Precision, Recall).
2.  **Response Evaluation:** Evaluate the quality and correctness of the final response.
3.  **Benchmarking:** Establish a baseline for agent performance on critical runbooks.

## Candidate Runbooks
We should start by selecting a few high-value runbooks that have well-defined workflows and tool usage patterns. Candidates include:

*   `rules-bank/run_books/triage_alerts.md`: This runbook has a clear sequence of steps (Context -> Duplicates -> Enrichment -> Assessment -> Action) and specific tool calls (`list_alerts_by_case`, `enrich_ioc`, `document_in_soar`, etc.), making it ideal for trajectory evaluation.
*   `rules-bank/run_books/investigate_a_gti_collection_id.md`: Involves specific lookups and investigation steps.
*   `rules-bank/run_books/ioc_threat_hunt.md`: Involves searching for IOCs and reporting findings.

## Action Items
1.  **Select Pilot Runbook:** Choose one runbook (e.g., `triage_alerts.md`) for the initial proof-of-concept.
2.  **Create Evaluation Dataset:** Construct a dataset containing input prompts and their corresponding "reference trajectories" (expected tool calls and arguments).
3.  **Implement Evaluation Script:** Use the Vertex AI Python SDK to run the evaluation.
    *   Define metrics (e.g., `trajectory_exact_match`, `trajectory_precision`).
    *   Run the agent against the dataset.
    *   Collect and report metrics.
4.  **Compare with LLM Judge:** Analyze how this automated evaluation complements the existing semantic evaluation provided by the `llm_judge`.
