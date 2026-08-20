# Promptfoo Evaluation Suite for ADK Runbooks

This directory contains the [Promptfoo](https://www.promptfoo.dev/) configuration, custom Python agent provider, and test suites for multi-turn agent evaluation, procedural compliance testing, and rubric grading across the `adk_runbooks` ecosystem.

## Full Documentation

For the complete architectural overview, rubric models, scoring criteria, and continuous integration workflows, see:
* **Sphinx Documentation**: [`rules-bank/ai/promptfoo_evaluation_manual.md`](../../rules-bank/ai/promptfoo_evaluation_manual.md)

---

## Directory Contents

* [`promptfooconfig.yaml`](./promptfooconfig.yaml): Declarative test configuration defining target prompts/personas, model providers (Gemini 3.7 Flash, 2.5 Flash, 2.5 Flash-Lite), test cases, and assertions (regex, string containment, LLM-as-a-judge rubrics).
* [`adk_agent_provider.py`](./adk_agent_provider.py): Custom Python provider bridging Promptfoo evaluations with the active ADK multi-agent execution loop.

---

## Quick Start

### 1. Run Evaluation via NPX
```bash
# Run all test cases in promptfooconfig.yaml
npx promptfoo@latest eval -c evals/promptfoo/promptfooconfig.yaml

# Export results to markdown and JSON
npx promptfoo@latest eval -c evals/promptfoo/promptfooconfig.yaml \
  -o ../results/promptfoo_eval.md \
  -o ../results/promptfoo_eval.json
```

### 2. View Results in Interactive Web UI
```bash
npx promptfoo@latest view
```

### 3. Compare Multiple Prompt Variants
```bash
npx promptfoo@latest eval \
  -p ../../rules-bank/personas/soc_analyst_tier1.md \
  -c evals/promptfoo/promptfooconfig.yaml \
  --table
```
