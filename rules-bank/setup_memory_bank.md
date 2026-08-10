# Setting up Vertex AI Memory Bank

This guide describes how to set up the Vertex AI Memory Bank for use with the ADK Manager Agent.

**Sources:**
*   [Vertex AI Agent Engine - Set up Memory Bank](https://cloud.google.com/vertex-ai/agent-builder/docs/agent-engine/memory-bank/set-up)
*   [Vertex AI Python SDK Reference](https://cloud.google.com/python/docs/reference/aiplatform/latest)

## Prerequisites

Ensure you have the Google Cloud SDK (`gcloud`) installed and authenticated.

### 1. Set Default Project

Set your Google Cloud project ID:

```bash
gcloud config set project YOUR_PROJECT_ID
```

### 2. Enable Required APIs

Enable the Vertex AI API:

```bash
gcloud services enable aiplatform.googleapis.com
```

### 3. Grant Permissions

Ensure your user (or the service account running the agent) has the `Vertex AI User` role:

```bash
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="user:your-email@example.com" \
    --role="roles/aiplatform.user"
```

## Creating the Memory Bank (Agent Engine)

While `gcloud` commands manage the infrastructure prerequisites, creating the Agent Engine with Memory Bank configuration is currently best done via the Vertex AI SDK for Python as it allows for complex configuration (memory topics, few-shot examples) that are difficult to pass via CLI.

### Create via Python SDK

1.  **Install the SDK:**

    ```bash
    pip install "google-cloud-aiplatform>=1.38.0"
    ```

2.  **Create the Memory Bank:**

    Create a script named `create_memory_bank.py` with the following content:

    ```python
    import vertexai
    # Note: Ensure you are using a version of the SDK that supports agent_engines
    from vertexai.preview import reasoning_engines

    # TODO: Replace with your project and location
    PROJECT_ID = "your-project-id"
    LOCATION = "us-central1"

    # Initialize Vertex AI
    vertexai.init(project=PROJECT_ID, location=LOCATION)

    print("Creating Agent Engine (Memory Bank)...")

    # Create an Agent Engine without a specific application to serve as a standalone Memory Bank
    # or with default configuration.
    try:
        remote_app = reasoning_engines.ReasoningEngine.create(
            reasoning_engine=None,
            requirements=[],
            display_name="ADK Memory Bank",
            description="Shared memory bank for ADK agents",
        )
        print(f"Successfully created Agent Engine.")
        print(f"Resource Name: {remote_app.resource_name}")
        # Extract ID
        engine_id = remote_app.resource_name.split('/')[-1]
        print(f"Agent Engine ID: {engine_id}")
        print("\nAdd the following to your .env file:")
        print(f"GOOGLE_CLOUD_AGENT_ENGINE_ID={engine_id}")

    except Exception as e:
        print(f"Error creating Agent Engine: {e}")
    ```

3.  **Run the script:**

    ```bash
    python create_memory_bank.py
    ```

## Integration

After creating the Memory Bank, update your `multi-agent/manager/.env` file to include the required environment variables so the Manager agent can connect to it.

```bash
GOOGLE_CLOUD_PROJECT=your-project-id
GOOGLE_CLOUD_LOCATION=us-central1
GOOGLE_CLOUD_AGENT_ENGINE_ID=YOUR_ENGINE_ID_FROM_ABOVE
```
