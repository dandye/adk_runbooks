# IP Address-Specific Atomic Runbooks

IP addresses are fundamental to network communications and are often key indicators in security alerts and investigations. Whether internal or external, an IP address can be associated with legitimate services, compromised systems, or malicious actors. The runbooks here provide steps to enrich IP addresses with threat intelligence, examine historical network traffic, and assess their role in security events.

```{toctree}
:maxdepth: 1
:caption: IP Address Runbooks:

rb_ip_get_gti_report
rb_ip_get_secops_threat_intel
rb_ip_lookup_entity_chronicle
rb_ip_search_network_traffic_chronicle


```

> **Save Findings to Memory:** If this workflow yielded novel insights (e.g., a new false positive rule, newly identified critical infrastructure, or a successful containment action), save these details to the memory bank under the appropriate topic (e.g., `analyst_notes`, `detection_rule_feedback`, or `containment_strategies`).
