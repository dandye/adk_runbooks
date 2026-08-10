
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Security Operations dynamic tool for searching security events."""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

# We import SecOpsClient directly since we are not running in the MCP server context
# Assumes 'secops' package is installed.
try:
    from secops import SecOpsClient
except ImportError:
    # Fallback or error handling if package is missing
    SecOpsClient = None


# Configure logging
logger = logging.getLogger('dynamic-security-search')
if not logger.handlers:
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.INFO)

# Default Chronicle configuration from environment variables
DEFAULT_PROJECT_ID = os.environ.get('CHRONICLE_PROJECT_ID', '725716774503')
DEFAULT_CUSTOMER_ID = os.environ.get(
    'CHRONICLE_CUSTOMER_ID', 'c3c6260c1c9340dcbbb802603bbf9636'
)
DEFAULT_REGION = os.environ.get('CHRONICLE_REGION', 'us')


def get_chronicle_client(
    project_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    region: Optional[str] = None
) -> Any:
    """Initialize and return a Chronicle client."""
    if not SecOpsClient:
        raise ImportError("secops package not installed.")

    # Use provided values or defaults from environment variables
    project_id = project_id or DEFAULT_PROJECT_ID
    customer_id = customer_id or DEFAULT_CUSTOMER_ID
    region = region or DEFAULT_REGION

    if not project_id or not customer_id:
        raise ValueError(
            'Chronicle project_id and customer_id must be provided either '
            'as parameters or through environment variables '
            '(CHRONICLE_PROJECT_ID, CHRONICLE_CUSTOMER_ID)'
        )

    client = SecOpsClient()
    chronicle = client.chronicle(
        customer_id=customer_id, project_id=project_id, region=region
    )
    return chronicle


def security_search(
    text: str,
    project_id: str = None,
    customer_id: str = None,
    hours_back: int = 24,
    max_events: int = 100,
    region: str = None,
) -> Dict[str, Any]:
    """Search for security events in Chronicle SIEM using natural language.

    Dynamic Tool Version: Optimized for Agentic Adaptation.
    """
    try:
        logger.info(f'Searching security events: {text}')

        chronicle = get_chronicle_client(project_id, customer_id, region)

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours_back)

        logger.info(f'Search time range: {start_time} to {end_time}')

        # Use the new natural language search method
        udm_query = chronicle.translate_nl_to_udm(text)
        logger.info(f'UDM Query: {udm_query}')

        events = chronicle.search_udm(
            query=udm_query,
            start_time=start_time,
            end_time=end_time,
            max_events=max_events,
        )

        # Transformation logic
        if isinstance(events, dict) and 'events' in events:
            total_events = events.get('total_events', 0)
            event_list = events.get('events', [])
        else:
            event_list = events if isinstance(events, list) else []
            total_events = len(event_list)
            events = {'events': event_list, 'total_events': total_events}

        return {'udm_query': udm_query, 'events': events, 'status': 'success'}

    except Exception as e:
        logger.error(f'Error searching security events: {str(e)}', exc_info=True)
        return {
            'udm_query': None,
            'events': {'error': str(e), 'events': [], 'total_events': 0},
            'status': 'error'
        }
