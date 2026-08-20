# ADK Workflow Benchmark (all_36_workflows)

**Generated:** 2026-08-19T14:00:09.958242+00:00  
**Total Evaluated:** 36 | **Passed:** 36 | **Failed:** 0 | **Pass Rate:** 100.0%  
**Average Score:** 89.7 / 100.0 | **Average Latency:** 0.0033s

---

## 1. Summary Scorecard Table

| Test ID | Workflow Name | Rubric Profile | Score | Duration | Status |
|:---|:---|:---:|:---:|:---:|:---:|
| `TEST-01-SUSPICIOUS-LOGIN` | `suspicious_login_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0170s | ✅ PASS |
| `TEST-02-MALWARE-TRIAGE` | `malware_triage_workflow` | `TRIAGE_IRP_RUBRIC` | **100.0** / 100.0 | 0.0034s | ✅ PASS |
| `TEST-03-BASIC-IOC-ENRICHMENT` | `basic_ioc_enrichment_workflow` | `TRIAGE_IRP_RUBRIC` | **95.0** / 100.0 | 0.0037s | ✅ PASS |
| `TEST-04-ENDPOINT-TRIAGE` | `endpoint_triage_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0031s | ✅ PASS |
| `TEST-05-IOC-CONTAINMENT` | `ioc_containment_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0025s | ✅ PASS |
| `TEST-06-CLOSE-DUPLICATES` | `close_duplicate_cases_workflow` | `TRIAGE_IRP_RUBRIC` | **88.0** / 100.0 | 0.0026s | ✅ PASS |
| `TEST-07-CLOUD-VULN-TRIAGE` | `cloud_vulnerability_triage_workflow` | `TRIAGE_IRP_RUBRIC` | **88.0** / 100.0 | 0.0027s | ✅ PASS |
| `TEST-08-COMPARE-GTI-COLLECTION` | `compare_gti_collection_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0042s | ✅ PASS |
| `TEST-09-CREATE-INVESTIGATION-REPORT` | `create_investigation_report_workflow` | `REPORTING_RUBRIC` | **95.0** / 100.0 | 0.0041s | ✅ PASS |
| `TEST-10-DEEP-DIVE-IOC-ANALYSIS` | `deep_dive_ioc_analysis_workflow` | `THREAT_HUNTING_RUBRIC` | **88.0** / 100.0 | 0.0036s | ✅ PASS |
| `TEST-11-DETECTION-RULE-VALIDATION` | `detection_rule_validation_workflow` | `DETECTION_ENGINEERING_RUBRIC` | **100.0** / 100.0 | 0.0032s | ✅ PASS |
| `TEST-12-CREDENTIAL-ACCESS-HUNT` | `credential_access_hunt_workflow` | `THREAT_HUNTING_RUBRIC` | **83.0** / 100.0 | 0.0035s | ✅ PASS |
| `TEST-13-INVESTIGATE-EXTERNAL-TOOLS` | `investigate_case_external_tools_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0019s | ✅ PASS |
| `TEST-14-LATERAL-MOVEMENT-HUNT` | `lateral_movement_hunt_workflow` | `THREAT_HUNTING_RUBRIC` | **83.0** / 100.0 | 0.0027s | ✅ PASS |
| `TEST-15-TRIAGE-ALERTS` | `triage_alerts_workflow` | `TRIAGE_IRP_RUBRIC` | **88.0** / 100.0 | 0.0021s | ✅ PASS |
| `TEST-16-ADVANCED-THREAT-HUNTING` | `advanced_threat_hunting_workflow` | `THREAT_HUNTING_RUBRIC` | **88.0** / 100.0 | 0.0024s | ✅ PASS |
| `TEST-17-ALERT-REPORT` | `alert_report_workflow` | `REPORTING_RUBRIC` | **100.0** / 100.0 | 0.0034s | ✅ PASS |
| `TEST-18-APT-THREAT-HUNT` | `apt_threat_hunt_workflow` | `THREAT_HUNTING_RUBRIC` | **83.0** / 100.0 | 0.0026s | ✅ PASS |
| `TEST-19-TIMELINE-PROCESS-ANALYSIS` | `timeline_process_analysis_workflow` | `REPORTING_RUBRIC` | **85.0** / 100.0 | 0.0024s | ✅ PASS |
| `TEST-20-CASE-REPORT` | `case_report_workflow` | `REPORTING_RUBRIC` | **95.0** / 100.0 | 0.0029s | ✅ PASS |
| `TEST-21-DETECTION-AS-CODE-TUNING` | `detection_as_code_tuning_workflow` | `DETECTION_ENGINEERING_RUBRIC` | **80.0** / 100.0 | 0.0027s | ✅ PASS |
| `TEST-22-DETECTION-REPORT` | `detection_report_workflow` | `REPORTING_RUBRIC` | **80.0** / 100.0 | 0.0026s | ✅ PASS |
| `TEST-23-GROUP-CASES` | `group_cases_workflow` | `TRIAGE_IRP_RUBRIC` | **88.0** / 100.0 | 0.0033s | ✅ PASS |
| `TEST-24-INVESTIGATE-GTI-COLLECTION` | `investigate_gti_collection_workflow` | `THREAT_HUNTING_RUBRIC` | **83.0** / 100.0 | 0.0028s | ✅ PASS |
| `TEST-25-IOC-THREAT-HUNT` | `ioc_threat_hunt_workflow` | `THREAT_HUNTING_RUBRIC` | **90.0** / 100.0 | 0.0032s | ✅ PASS |
| `TEST-26-POST-INCIDENT-REVIEW` | `post_incident_review_workflow` | `THREAT_HUNTING_RUBRIC` | **83.0** / 100.0 | 0.0028s | ✅ PASS |
| `TEST-27-PRIORITIZE-INVESTIGATE-CASE` | `prioritize_investigate_case_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0032s | ✅ PASS |
| `TEST-28-PROACTIVE-GTI-THREAT-HUNT` | `proactive_gti_threat_hunt_workflow` | `THREAT_HUNTING_RUBRIC` | **83.0** / 100.0 | 0.0028s | ✅ PASS |
| `TEST-29-UEBA-REPORT` | `ueba_report_workflow` | `REPORTING_RUBRIC` | **90.0** / 100.0 | 0.0028s | ✅ PASS |
| `TEST-30-COMPROMISED-USER-IRP` | `compromised_user_irp_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0028s | ✅ PASS |
| `TEST-31-MALWARE-IRP` | `malware_irp_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0045s | ✅ PASS |
| `TEST-32-PHISHING-IRP` | `phishing_irp_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0024s | ✅ PASS |
| `TEST-33-RANSOMWARE-IRP` | `ransomware_irp_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0021s | ✅ PASS |
| `TEST-34-DEMO-SOC-T2` | `demo_soc_t2_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0025s | ✅ PASS |
| `TEST-35-GROUP-CASES-V2` | `group_cases_v2_workflow` | `TRIAGE_IRP_RUBRIC` | **88.0** / 100.0 | 0.0024s | ✅ PASS |
| `TEST-36-METAANALYSIS` | `metaanalysis_workflow` | `THREAT_HUNTING_RUBRIC` | **83.0** / 100.0 | 0.0029s | ✅ PASS |

---

## 2. Detailed Feedback & Category Breakdown

### `TEST-01-SUSPICIOUS-LOGIN`: suspicious_login_workflow
* **Verdict:** PASS (Score: 93.0/100.0)
* **Category Scores:**
  * **Context & Enrichment:** 18.0 pts
  * **Analysis & Decision:** 25.0 pts
  * **Action Execution:** 20.0 pts
  * **Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Entity Extraction (10/10): Accurately identified target indicators and involved entities.
  - Context Enrichment (8/15): Limited context enrichment observed.
  - Telemetry Interpretation (15/15): Interpreted risk context and alert severity accurately.
  - Decision Logic (10/10): Reached deterministic disposition or containment decision.
  - Action Execution (20/20): Executed required response/triage actions and verified status.
  - Documentation (15/15): Comprehensive SOAR case notes and action summary recorded.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated clear outcome summary.

### `TEST-02-MALWARE-TRIAGE`: malware_triage_workflow
* **Verdict:** PASS (Score: 100.0/100.0)
* **Category Scores:**
  * **Context & Enrichment:** 25.0 pts
  * **Analysis & Decision:** 25.0 pts
  * **Action Execution:** 20.0 pts
  * **Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Entity Extraction (10/10): Accurately identified target indicators and involved entities.
  - Context Enrichment (15/15): Performed SIEM and Threat Intelligence contextual lookups.
  - Telemetry Interpretation (15/15): Interpreted risk context and alert severity accurately.
  - Decision Logic (10/10): Reached deterministic disposition or containment decision.
  - Action Execution (20/20): Executed required response/triage actions and verified status.
  - Documentation (15/15): Comprehensive SOAR case notes and action summary recorded.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated clear outcome summary.

### `TEST-03-BASIC-IOC-ENRICHMENT`: basic_ioc_enrichment_workflow
* **Verdict:** PASS (Score: 95.0/100.0)
* **Category Scores:**
  * **Context & Enrichment:** 25.0 pts
  * **Analysis & Decision:** 25.0 pts
  * **Action Execution:** 20.0 pts
  * **Documentation:** 10.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Entity Extraction (10/10): Accurately identified target indicators and involved entities.
  - Context Enrichment (15/15): Performed SIEM and Threat Intelligence contextual lookups.
  - Telemetry Interpretation (15/15): Interpreted risk context and alert severity accurately.
  - Decision Logic (10/10): Reached deterministic disposition or containment decision.
  - Action Execution (20/20): Executed required response/triage actions and verified status.
  - Documentation (10/15): Recorded brief case documentation.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated clear outcome summary.

### `TEST-04-ENDPOINT-TRIAGE`: endpoint_triage_workflow
* **Verdict:** PASS (Score: 93.0/100.0)
* **Category Scores:**
  * **Context & Enrichment:** 18.0 pts
  * **Analysis & Decision:** 25.0 pts
  * **Action Execution:** 20.0 pts
  * **Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Entity Extraction (10/10): Accurately identified target indicators and involved entities.
  - Context Enrichment (8/15): Limited context enrichment observed.
  - Telemetry Interpretation (15/15): Interpreted risk context and alert severity accurately.
  - Decision Logic (10/10): Reached deterministic disposition or containment decision.
  - Action Execution (20/20): Executed required response/triage actions and verified status.
  - Documentation (15/15): Comprehensive SOAR case notes and action summary recorded.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated clear outcome summary.

### `TEST-05-IOC-CONTAINMENT`: ioc_containment_workflow
* **Verdict:** PASS (Score: 93.0/100.0)
* **Category Scores:**
  * **Context & Enrichment:** 18.0 pts
  * **Analysis & Decision:** 25.0 pts
  * **Action Execution:** 20.0 pts
  * **Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Entity Extraction (10/10): Accurately identified target indicators and involved entities.
  - Context Enrichment (8/15): Limited context enrichment observed.
  - Telemetry Interpretation (15/15): Interpreted risk context and alert severity accurately.
  - Decision Logic (10/10): Reached deterministic disposition or containment decision.
  - Action Execution (20/20): Executed required response/triage actions and verified status.
  - Documentation (15/15): Comprehensive SOAR case notes and action summary recorded.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated clear outcome summary.

### `TEST-06-CLOSE-DUPLICATES`: close_duplicate_cases_workflow
* **Verdict:** PASS (Score: 88.0/100.0)
* **Category Scores:**
  * **Context & Enrichment:** 13.0 pts
  * **Analysis & Decision:** 25.0 pts
  * **Action Execution:** 20.0 pts
  * **Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Entity Extraction (5/10): Missing explicit entity identifiers.
  - Context Enrichment (8/15): Limited context enrichment observed.
  - Telemetry Interpretation (15/15): Interpreted risk context and alert severity accurately.
  - Decision Logic (10/10): Reached deterministic disposition or containment decision.
  - Action Execution (20/20): Executed required response/triage actions and verified status.
  - Documentation (15/15): Comprehensive SOAR case notes and action summary recorded.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated clear outcome summary.

### `TEST-07-CLOUD-VULN-TRIAGE`: cloud_vulnerability_triage_workflow
* **Verdict:** PASS (Score: 88.0/100.0)
* **Category Scores:**
  * **Context & Enrichment:** 13.0 pts
  * **Analysis & Decision:** 25.0 pts
  * **Action Execution:** 20.0 pts
  * **Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Entity Extraction (5/10): Missing explicit entity identifiers.
  - Context Enrichment (8/15): Limited context enrichment observed.
  - Telemetry Interpretation (15/15): Interpreted risk context and alert severity accurately.
  - Decision Logic (10/10): Reached deterministic disposition or containment decision.
  - Action Execution (20/20): Executed required response/triage actions and verified status.
  - Documentation (15/15): Comprehensive SOAR case notes and action summary recorded.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated clear outcome summary.

### `TEST-08-COMPARE-GTI-COLLECTION`: compare_gti_collection_workflow
* **Verdict:** PASS (Score: 93.0/100.0)
* **Category Scores:**
  * **Context & Enrichment:** 18.0 pts
  * **Analysis & Decision:** 25.0 pts
  * **Action Execution:** 20.0 pts
  * **Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Entity Extraction (10/10): Accurately identified target indicators and involved entities.
  - Context Enrichment (8/15): Limited context enrichment observed.
  - Telemetry Interpretation (15/15): Interpreted risk context and alert severity accurately.
  - Decision Logic (10/10): Reached deterministic disposition or containment decision.
  - Action Execution (20/20): Executed required response/triage actions and verified status.
  - Documentation (15/15): Comprehensive SOAR case notes and action summary recorded.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated clear outcome summary.

### `TEST-09-CREATE-INVESTIGATION-REPORT`: create_investigation_report_workflow
* **Verdict:** PASS (Score: 95.0/100.0)
* **Category Scores:**
  * **Data Collection:** 25.0 pts
  * **Report Generation:** 25.0 pts
  * **Quality & Clarity:** 15.0 pts
  * **Delivery:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Data Collection (25/25): Successfully collected case telemetry and alert entities.
  - Report Formatting (15/15): Properly formatted into structured Markdown.
  - Required Sections (10/15): Partial section coverage.
  - Quality & Clarity (15/15): Coherent, technically accurate, and professional.
  - Delivery (15/15): Successfully written to file / SOAR documentation path.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and token/cost telemetry.
  - Summary Report (5/5): Provided concise action/outcome summary.

### `TEST-10-DEEP-DIVE-IOC-ANALYSIS`: deep_dive_ioc_analysis_workflow
* **Verdict:** PASS (Score: 88.0/100.0)
* **Category Scores:**
  * **Scope & Query:** 18.0 pts
  * **Data Analysis & Correlation:** 25.0 pts
  * **Findings Classification:** 15.0 pts
  * **Hunt Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Hunt Scope (10/10): Defined clear time range, target entities, and hunt scope.
  - Query Execution (8/15): Limited empirical query results returned.
  - Data Analysis (15/15): Analyzed returned telemetry for anomalous adversary patterns.
  - Telemetry Correlation (10/15): Partial cross-data source correlation.
  - Findings Classification (15/15): Accurately classified findings (True Positives vs Benign).
  - Hunt Documentation (15/15): Recorded comprehensive hunt methodology and findings in SOAR.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated actionable hunt lead summary.

### `TEST-11-DETECTION-RULE-VALIDATION`: detection_rule_validation_workflow
* **Verdict:** PASS (Score: 100.0/100.0)
* **Category Scores:**
  * **Requirement Analysis:** 20.0 pts
  * **Technical Implementation:** 30.0 pts
  * **Validation & Testing:** 20.0 pts
  * **Git/Process Compliance:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Requirement Analysis (20/20): Accurately identified detection rule scope and validation targets.
  - Syntax Validation (15/15): Verified YARA-L / detection rule syntax compilation.
  - Rule Logic (15/15): Verified detection logic alignment with attack techniques.
  - Validation & Testing (20/20): Tested against historical SIEM telemetry and calculated FP ratios.
  - Process Compliance (15/15): Formulated explicit deployment/tuning recommendation.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Produced concise validation summary.

### `TEST-12-CREDENTIAL-ACCESS-HUNT`: credential_access_hunt_workflow
* **Verdict:** PASS (Score: 83.0/100.0)
* **Category Scores:**
  * **Scope & Query:** 13.0 pts
  * **Data Analysis & Correlation:** 25.0 pts
  * **Findings Classification:** 15.0 pts
  * **Hunt Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Hunt Scope (5/10): Partial hunt scope definition.
  - Query Execution (8/15): Limited empirical query results returned.
  - Data Analysis (15/15): Analyzed returned telemetry for anomalous adversary patterns.
  - Telemetry Correlation (10/15): Partial cross-data source correlation.
  - Findings Classification (15/15): Accurately classified findings (True Positives vs Benign).
  - Hunt Documentation (15/15): Recorded comprehensive hunt methodology and findings in SOAR.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated actionable hunt lead summary.

### `TEST-13-INVESTIGATE-EXTERNAL-TOOLS`: investigate_case_external_tools_workflow
* **Verdict:** PASS (Score: 93.0/100.0)
* **Category Scores:**
  * **Context & Enrichment:** 18.0 pts
  * **Analysis & Decision:** 25.0 pts
  * **Action Execution:** 20.0 pts
  * **Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Entity Extraction (10/10): Accurately identified target indicators and involved entities.
  - Context Enrichment (8/15): Limited context enrichment observed.
  - Telemetry Interpretation (15/15): Interpreted risk context and alert severity accurately.
  - Decision Logic (10/10): Reached deterministic disposition or containment decision.
  - Action Execution (20/20): Executed required response/triage actions and verified status.
  - Documentation (15/15): Comprehensive SOAR case notes and action summary recorded.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated clear outcome summary.

### `TEST-14-LATERAL-MOVEMENT-HUNT`: lateral_movement_hunt_workflow
* **Verdict:** PASS (Score: 83.0/100.0)
* **Category Scores:**
  * **Scope & Query:** 13.0 pts
  * **Data Analysis & Correlation:** 25.0 pts
  * **Findings Classification:** 15.0 pts
  * **Hunt Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Hunt Scope (5/10): Partial hunt scope definition.
  - Query Execution (8/15): Limited empirical query results returned.
  - Data Analysis (15/15): Analyzed returned telemetry for anomalous adversary patterns.
  - Telemetry Correlation (10/15): Partial cross-data source correlation.
  - Findings Classification (15/15): Accurately classified findings (True Positives vs Benign).
  - Hunt Documentation (15/15): Recorded comprehensive hunt methodology and findings in SOAR.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated actionable hunt lead summary.

### `TEST-15-TRIAGE-ALERTS`: triage_alerts_workflow
* **Verdict:** PASS (Score: 88.0/100.0)
* **Category Scores:**
  * **Context & Enrichment:** 13.0 pts
  * **Analysis & Decision:** 25.0 pts
  * **Action Execution:** 20.0 pts
  * **Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Entity Extraction (5/10): Missing explicit entity identifiers.
  - Context Enrichment (8/15): Limited context enrichment observed.
  - Telemetry Interpretation (15/15): Interpreted risk context and alert severity accurately.
  - Decision Logic (10/10): Reached deterministic disposition or containment decision.
  - Action Execution (20/20): Executed required response/triage actions and verified status.
  - Documentation (15/15): Comprehensive SOAR case notes and action summary recorded.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated clear outcome summary.

### `TEST-16-ADVANCED-THREAT-HUNTING`: advanced_threat_hunting_workflow
* **Verdict:** PASS (Score: 88.0/100.0)
* **Category Scores:**
  * **Scope & Query:** 13.0 pts
  * **Data Analysis & Correlation:** 30.0 pts
  * **Findings Classification:** 15.0 pts
  * **Hunt Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Hunt Scope (5/10): Partial hunt scope definition.
  - Query Execution (8/15): Limited empirical query results returned.
  - Data Analysis (15/15): Analyzed returned telemetry for anomalous adversary patterns.
  - Telemetry Correlation (15/15): Correlated host activity, network events, and threat intelligence.
  - Findings Classification (15/15): Accurately classified findings (True Positives vs Benign).
  - Hunt Documentation (15/15): Recorded comprehensive hunt methodology and findings in SOAR.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated actionable hunt lead summary.

### `TEST-17-ALERT-REPORT`: alert_report_workflow
* **Verdict:** PASS (Score: 100.0/100.0)
* **Category Scores:**
  * **Data Collection:** 25.0 pts
  * **Report Generation:** 30.0 pts
  * **Quality & Clarity:** 15.0 pts
  * **Delivery:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Data Collection (25/25): Successfully collected case telemetry and alert entities.
  - Report Formatting (15/15): Properly formatted into structured Markdown.
  - Required Sections (15/15): All key reporting sections present.
  - Quality & Clarity (15/15): Coherent, technically accurate, and professional.
  - Delivery (15/15): Successfully written to file / SOAR documentation path.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and token/cost telemetry.
  - Summary Report (5/5): Provided concise action/outcome summary.

### `TEST-18-APT-THREAT-HUNT`: apt_threat_hunt_workflow
* **Verdict:** PASS (Score: 83.0/100.0)
* **Category Scores:**
  * **Scope & Query:** 13.0 pts
  * **Data Analysis & Correlation:** 25.0 pts
  * **Findings Classification:** 15.0 pts
  * **Hunt Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Hunt Scope (5/10): Partial hunt scope definition.
  - Query Execution (8/15): Limited empirical query results returned.
  - Data Analysis (15/15): Analyzed returned telemetry for anomalous adversary patterns.
  - Telemetry Correlation (10/15): Partial cross-data source correlation.
  - Findings Classification (15/15): Accurately classified findings (True Positives vs Benign).
  - Hunt Documentation (15/15): Recorded comprehensive hunt methodology and findings in SOAR.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated actionable hunt lead summary.

### `TEST-19-TIMELINE-PROCESS-ANALYSIS`: timeline_process_analysis_workflow
* **Verdict:** PASS (Score: 85.0/100.0)
* **Category Scores:**
  * **Data Collection:** 25.0 pts
  * **Report Generation:** 20.0 pts
  * **Quality & Clarity:** 10.0 pts
  * **Delivery:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Data Collection (25/25): Successfully collected case telemetry and alert entities.
  - Report Formatting (15/15): Properly formatted into structured Markdown.
  - Required Sections (5/15): Incomplete section structure.
  - Quality & Clarity (10/15): Readable with minor content density gaps.
  - Delivery (15/15): Successfully written to file / SOAR documentation path.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and token/cost telemetry.
  - Summary Report (5/5): Provided concise action/outcome summary.

### `TEST-20-CASE-REPORT`: case_report_workflow
* **Verdict:** PASS (Score: 95.0/100.0)
* **Category Scores:**
  * **Data Collection:** 25.0 pts
  * **Report Generation:** 25.0 pts
  * **Quality & Clarity:** 15.0 pts
  * **Delivery:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Data Collection (25/25): Successfully collected case telemetry and alert entities.
  - Report Formatting (15/15): Properly formatted into structured Markdown.
  - Required Sections (10/15): Partial section coverage.
  - Quality & Clarity (15/15): Coherent, technically accurate, and professional.
  - Delivery (15/15): Successfully written to file / SOAR documentation path.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and token/cost telemetry.
  - Summary Report (5/5): Provided concise action/outcome summary.

### `TEST-21-DETECTION-AS-CODE-TUNING`: detection_as_code_tuning_workflow
* **Verdict:** PASS (Score: 80.0/100.0)
* **Category Scores:**
  * **Requirement Analysis:** 20.0 pts
  * **Technical Implementation:** 20.0 pts
  * **Validation & Testing:** 10.0 pts
  * **Git/Process Compliance:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Requirement Analysis (20/20): Accurately identified detection rule scope and validation targets.
  - Syntax Validation (5/15): Syntax verification incomplete.
  - Rule Logic (15/15): Verified detection logic alignment with attack techniques.
  - Validation & Testing (10/20): Limited empirical telemetry testing.
  - Process Compliance (15/15): Formulated explicit deployment/tuning recommendation.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Produced concise validation summary.

### `TEST-22-DETECTION-REPORT`: detection_report_workflow
* **Verdict:** PASS (Score: 80.0/100.0)
* **Category Scores:**
  * **Data Collection:** 20.0 pts
  * **Report Generation:** 20.0 pts
  * **Quality & Clarity:** 10.0 pts
  * **Delivery:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Data Collection (20/25): Data collected with partial entity attribution.
  - Report Formatting (15/15): Properly formatted into structured Markdown.
  - Required Sections (5/15): Incomplete section structure.
  - Quality & Clarity (10/15): Readable with minor content density gaps.
  - Delivery (15/15): Successfully written to file / SOAR documentation path.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and token/cost telemetry.
  - Summary Report (5/5): Provided concise action/outcome summary.

### `TEST-23-GROUP-CASES`: group_cases_workflow
* **Verdict:** PASS (Score: 88.0/100.0)
* **Category Scores:**
  * **Context & Enrichment:** 13.0 pts
  * **Analysis & Decision:** 25.0 pts
  * **Action Execution:** 20.0 pts
  * **Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Entity Extraction (5/10): Missing explicit entity identifiers.
  - Context Enrichment (8/15): Limited context enrichment observed.
  - Telemetry Interpretation (15/15): Interpreted risk context and alert severity accurately.
  - Decision Logic (10/10): Reached deterministic disposition or containment decision.
  - Action Execution (20/20): Executed required response/triage actions and verified status.
  - Documentation (15/15): Comprehensive SOAR case notes and action summary recorded.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated clear outcome summary.

### `TEST-24-INVESTIGATE-GTI-COLLECTION`: investigate_gti_collection_workflow
* **Verdict:** PASS (Score: 83.0/100.0)
* **Category Scores:**
  * **Scope & Query:** 13.0 pts
  * **Data Analysis & Correlation:** 25.0 pts
  * **Findings Classification:** 15.0 pts
  * **Hunt Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Hunt Scope (5/10): Partial hunt scope definition.
  - Query Execution (8/15): Limited empirical query results returned.
  - Data Analysis (15/15): Analyzed returned telemetry for anomalous adversary patterns.
  - Telemetry Correlation (10/15): Partial cross-data source correlation.
  - Findings Classification (15/15): Accurately classified findings (True Positives vs Benign).
  - Hunt Documentation (15/15): Recorded comprehensive hunt methodology and findings in SOAR.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated actionable hunt lead summary.

### `TEST-25-IOC-THREAT-HUNT`: ioc_threat_hunt_workflow
* **Verdict:** PASS (Score: 90.0/100.0)
* **Category Scores:**
  * **Scope & Query:** 20.0 pts
  * **Data Analysis & Correlation:** 25.0 pts
  * **Findings Classification:** 15.0 pts
  * **Hunt Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Hunt Scope (5/10): Partial hunt scope definition.
  - Query Execution (15/15): Constructed and executed targeted SIEM / UDM queries.
  - Data Analysis (15/15): Analyzed returned telemetry for anomalous adversary patterns.
  - Telemetry Correlation (10/15): Partial cross-data source correlation.
  - Findings Classification (15/15): Accurately classified findings (True Positives vs Benign).
  - Hunt Documentation (15/15): Recorded comprehensive hunt methodology and findings in SOAR.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated actionable hunt lead summary.

### `TEST-26-POST-INCIDENT-REVIEW`: post_incident_review_workflow
* **Verdict:** PASS (Score: 83.0/100.0)
* **Category Scores:**
  * **Scope & Query:** 13.0 pts
  * **Data Analysis & Correlation:** 25.0 pts
  * **Findings Classification:** 15.0 pts
  * **Hunt Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Hunt Scope (5/10): Partial hunt scope definition.
  - Query Execution (8/15): Limited empirical query results returned.
  - Data Analysis (15/15): Analyzed returned telemetry for anomalous adversary patterns.
  - Telemetry Correlation (10/15): Partial cross-data source correlation.
  - Findings Classification (15/15): Accurately classified findings (True Positives vs Benign).
  - Hunt Documentation (15/15): Recorded comprehensive hunt methodology and findings in SOAR.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated actionable hunt lead summary.

### `TEST-27-PRIORITIZE-INVESTIGATE-CASE`: prioritize_investigate_case_workflow
* **Verdict:** PASS (Score: 93.0/100.0)
* **Category Scores:**
  * **Context & Enrichment:** 18.0 pts
  * **Analysis & Decision:** 25.0 pts
  * **Action Execution:** 20.0 pts
  * **Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Entity Extraction (10/10): Accurately identified target indicators and involved entities.
  - Context Enrichment (8/15): Limited context enrichment observed.
  - Telemetry Interpretation (15/15): Interpreted risk context and alert severity accurately.
  - Decision Logic (10/10): Reached deterministic disposition or containment decision.
  - Action Execution (20/20): Executed required response/triage actions and verified status.
  - Documentation (15/15): Comprehensive SOAR case notes and action summary recorded.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated clear outcome summary.

### `TEST-28-PROACTIVE-GTI-THREAT-HUNT`: proactive_gti_threat_hunt_workflow
* **Verdict:** PASS (Score: 83.0/100.0)
* **Category Scores:**
  * **Scope & Query:** 13.0 pts
  * **Data Analysis & Correlation:** 25.0 pts
  * **Findings Classification:** 15.0 pts
  * **Hunt Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Hunt Scope (5/10): Partial hunt scope definition.
  - Query Execution (8/15): Limited empirical query results returned.
  - Data Analysis (15/15): Analyzed returned telemetry for anomalous adversary patterns.
  - Telemetry Correlation (10/15): Partial cross-data source correlation.
  - Findings Classification (15/15): Accurately classified findings (True Positives vs Benign).
  - Hunt Documentation (15/15): Recorded comprehensive hunt methodology and findings in SOAR.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated actionable hunt lead summary.

### `TEST-29-UEBA-REPORT`: ueba_report_workflow
* **Verdict:** PASS (Score: 90.0/100.0)
* **Category Scores:**
  * **Data Collection:** 25.0 pts
  * **Report Generation:** 20.0 pts
  * **Quality & Clarity:** 15.0 pts
  * **Delivery:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Data Collection (25/25): Successfully collected case telemetry and alert entities.
  - Report Formatting (15/15): Properly formatted into structured Markdown.
  - Required Sections (5/15): Incomplete section structure.
  - Quality & Clarity (15/15): Coherent, technically accurate, and professional.
  - Delivery (15/15): Successfully written to file / SOAR documentation path.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and token/cost telemetry.
  - Summary Report (5/5): Provided concise action/outcome summary.

### `TEST-30-COMPROMISED-USER-IRP`: compromised_user_irp_workflow
* **Verdict:** PASS (Score: 93.0/100.0)
* **Category Scores:**
  * **Context & Enrichment:** 18.0 pts
  * **Analysis & Decision:** 25.0 pts
  * **Action Execution:** 20.0 pts
  * **Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Entity Extraction (10/10): Accurately identified target indicators and involved entities.
  - Context Enrichment (8/15): Limited context enrichment observed.
  - Telemetry Interpretation (15/15): Interpreted risk context and alert severity accurately.
  - Decision Logic (10/10): Reached deterministic disposition or containment decision.
  - Action Execution (20/20): Executed required response/triage actions and verified status.
  - Documentation (15/15): Comprehensive SOAR case notes and action summary recorded.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated clear outcome summary.

### `TEST-31-MALWARE-IRP`: malware_irp_workflow
* **Verdict:** PASS (Score: 93.0/100.0)
* **Category Scores:**
  * **Context & Enrichment:** 18.0 pts
  * **Analysis & Decision:** 25.0 pts
  * **Action Execution:** 20.0 pts
  * **Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Entity Extraction (10/10): Accurately identified target indicators and involved entities.
  - Context Enrichment (8/15): Limited context enrichment observed.
  - Telemetry Interpretation (15/15): Interpreted risk context and alert severity accurately.
  - Decision Logic (10/10): Reached deterministic disposition or containment decision.
  - Action Execution (20/20): Executed required response/triage actions and verified status.
  - Documentation (15/15): Comprehensive SOAR case notes and action summary recorded.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated clear outcome summary.

### `TEST-32-PHISHING-IRP`: phishing_irp_workflow
* **Verdict:** PASS (Score: 93.0/100.0)
* **Category Scores:**
  * **Context & Enrichment:** 18.0 pts
  * **Analysis & Decision:** 25.0 pts
  * **Action Execution:** 20.0 pts
  * **Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Entity Extraction (10/10): Accurately identified target indicators and involved entities.
  - Context Enrichment (8/15): Limited context enrichment observed.
  - Telemetry Interpretation (15/15): Interpreted risk context and alert severity accurately.
  - Decision Logic (10/10): Reached deterministic disposition or containment decision.
  - Action Execution (20/20): Executed required response/triage actions and verified status.
  - Documentation (15/15): Comprehensive SOAR case notes and action summary recorded.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated clear outcome summary.

### `TEST-33-RANSOMWARE-IRP`: ransomware_irp_workflow
* **Verdict:** PASS (Score: 93.0/100.0)
* **Category Scores:**
  * **Context & Enrichment:** 18.0 pts
  * **Analysis & Decision:** 25.0 pts
  * **Action Execution:** 20.0 pts
  * **Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Entity Extraction (10/10): Accurately identified target indicators and involved entities.
  - Context Enrichment (8/15): Limited context enrichment observed.
  - Telemetry Interpretation (15/15): Interpreted risk context and alert severity accurately.
  - Decision Logic (10/10): Reached deterministic disposition or containment decision.
  - Action Execution (20/20): Executed required response/triage actions and verified status.
  - Documentation (15/15): Comprehensive SOAR case notes and action summary recorded.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated clear outcome summary.

### `TEST-34-DEMO-SOC-T2`: demo_soc_t2_workflow
* **Verdict:** PASS (Score: 93.0/100.0)
* **Category Scores:**
  * **Context & Enrichment:** 18.0 pts
  * **Analysis & Decision:** 25.0 pts
  * **Action Execution:** 20.0 pts
  * **Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Entity Extraction (10/10): Accurately identified target indicators and involved entities.
  - Context Enrichment (8/15): Limited context enrichment observed.
  - Telemetry Interpretation (15/15): Interpreted risk context and alert severity accurately.
  - Decision Logic (10/10): Reached deterministic disposition or containment decision.
  - Action Execution (20/20): Executed required response/triage actions and verified status.
  - Documentation (15/15): Comprehensive SOAR case notes and action summary recorded.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated clear outcome summary.

### `TEST-35-GROUP-CASES-V2`: group_cases_v2_workflow
* **Verdict:** PASS (Score: 88.0/100.0)
* **Category Scores:**
  * **Context & Enrichment:** 13.0 pts
  * **Analysis & Decision:** 25.0 pts
  * **Action Execution:** 20.0 pts
  * **Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Entity Extraction (5/10): Missing explicit entity identifiers.
  - Context Enrichment (8/15): Limited context enrichment observed.
  - Telemetry Interpretation (15/15): Interpreted risk context and alert severity accurately.
  - Decision Logic (10/10): Reached deterministic disposition or containment decision.
  - Action Execution (20/20): Executed required response/triage actions and verified status.
  - Documentation (15/15): Comprehensive SOAR case notes and action summary recorded.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated clear outcome summary.

### `TEST-36-METAANALYSIS`: metaanalysis_workflow
* **Verdict:** PASS (Score: 83.0/100.0)
* **Category Scores:**
  * **Scope & Query:** 13.0 pts
  * **Data Analysis & Correlation:** 25.0 pts
  * **Findings Classification:** 15.0 pts
  * **Hunt Documentation:** 15.0 pts
  * **Operational Artifacts:** 15.0 pts
* **Rubric Feedback:**
  - Hunt Scope (5/10): Partial hunt scope definition.
  - Query Execution (8/15): Limited empirical query results returned.
  - Data Analysis (15/15): Analyzed returned telemetry for anomalous adversary patterns.
  - Telemetry Correlation (10/15): Partial cross-data source correlation.
  - Findings Classification (15/15): Accurately classified findings (True Positives vs Benign).
  - Hunt Documentation (15/15): Recorded comprehensive hunt methodology and findings in SOAR.
  - Sequence Diagram (5/5): Included workflow sequence visualization.
  - Execution Metadata (5/5): Recorded execution duration and telemetry.
  - Summary Report (5/5): Generated actionable hunt lead summary.
