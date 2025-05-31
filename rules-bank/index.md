# Rules Bank Documentation

Welcome to the Rules Bank! This site provides a comprehensive overview of detection rules, strategies, and operational procedures.

```{toctree}
:maxdepth: 2
:caption: Contents:

# --- Core Documents ---
indicator_handling_protocols
detection_strategy
project_plan
mcp_tool_best_practices
# (Add other top-level .md files from rules-bank/ here, without .md extension)


# --- Subdirectories / Atomic Runbooks ---
# (Ensure paths are relative to this index.md file, which is at the root of rules-bank/)
# Example:
atomic_runbooks/ip_address/rb_ip_get_gti_report
atomic_runbooks/domain/rb_domain_get_gti_report
atomic_runbooks/hash/rb_hash_get_gti_report
atomic_runbooks/url/rb_url_get_gti_report
atomic_runbooks/user/rb_user_lookup_entity_chronicle
# (List other runbooks or create nested toctrees in subdirectory index files)

# --- Other Sections ---
detection_use_cases/duc_template_package
runbook_templates/atomic_runbook_template
# (Add other .md files or sub-directory references as needed)
