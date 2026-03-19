# Common Investigation Steps

Effective security operations often involve recurring tasks and procedures. This section isolates common, reusable steps that are frequently incorporated into larger, more comprehensive investigation and response runbooks. Documenting these common steps here promotes consistency, reduces redundancy, and simplifies the construction and maintenance of broader workflows.

```{toctree}
:maxdepth: 1
:caption: Common Steps:

check_duplicate_cases
close_soar_artifact
confirm_action
correlate_ioc_with_alerts_cases
document_in_soar
enrich_ioc
find_relevant_soar_case
generate_report_file
pivot_on_ioc_gti


```

> **Save Findings to Memory:** If this workflow yielded novel insights (e.g., a new false positive rule, newly identified critical infrastructure, or a successful containment action), save these details to the memory bank under the appropriate topic (e.g., `analyst_notes`, `detection_rule_feedback`, or `containment_strategies`).
