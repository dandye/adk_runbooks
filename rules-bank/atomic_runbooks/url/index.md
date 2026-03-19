# URL-Specific Atomic Runbooks

URLs are common in alerts related to web-based threats, phishing campaigns, and malware delivery. These atomic runbooks provide procedures to analyze URLs, retrieve threat intelligence, and search for their occurrences in logs, helping to determine their maliciousness and impact.

```{toctree}
:maxdepth: 1
:caption: URL Runbooks:

rb_url_get_gti_report
rb_url_get_secops_threat_intel
rb_url_search_chronicle


```

> **Save Findings to Memory:** If this workflow yielded novel insights (e.g., a new false positive rule, newly identified critical infrastructure, or a successful containment action), save these details to the memory bank under the appropriate topic (e.g., `analyst_notes`, `detection_rule_feedback`, or `containment_strategies`).
