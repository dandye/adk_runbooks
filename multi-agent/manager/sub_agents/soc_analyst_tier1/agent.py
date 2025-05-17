from google.adk.agents import Agent
from google.adk.tools import google_search

soc_analyst_tier1 = Agent(
    name="soc_analyst_tier1",
    model="gemini-2.0-flash",
    description="SOC Analyst Tier 1",
    instruction="""
    You are a Tier 1 SOC Analyst.
    """,
    tools=[google_search],
)
