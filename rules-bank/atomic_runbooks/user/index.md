# User-Specific Atomic Runbooks

User accounts are often targeted by attackers or can be involved in insider threats. Investigating user activity, such as login patterns, process executions, and resource access, is crucial for detecting and responding to potential compromises. These atomic runbooks provide focused procedures for analyzing user-related indicators and events.

```{toctree}
:maxdepth: 1
:caption: User Runbooks:

rb_user_lookup_entity_chronicle
rb_user_search_login_activity_chronicle
rb_user_search_process_activity_chronicle


```

> **Save Findings to Memory:** If this workflow yielded novel insights (e.g., a new false positive rule, newly identified critical infrastructure, or a successful containment action), save these details to the memory bank under the appropriate topic (e.g., `analyst_notes`, `detection_rule_feedback`, or `containment_strategies`).
