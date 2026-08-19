# ADK Workflow Benchmark (core_workflows)

**Generated:** 2026-08-19T03:28:12.093083+00:00  
**Total Evaluated:** 10 | **Passed:** 10 | **Failed:** 0 | **Pass Rate:** 100.0%  
**Average Score:** 95.5 / 100.0 | **Average Latency:** 0.0048s

---

## 1. Summary Scorecard Table

| Test ID | Workflow Name | Rubric Profile | Score | Duration | Status |
|:---|:---|:---:|:---:|:---:|:---:|
| `TEST-CORE-SUSP-LOGIN-001` | `suspicious_login_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0142s | ✅ PASS |
| `TEST-CORE-SUSP-LOGIN-002` | `suspicious_login_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0025s | ✅ PASS |
| `TEST-CORE-MALWARE-001` | `malware_triage_workflow` | `TRIAGE_IRP_RUBRIC` | **100.0** / 100.0 | 0.0023s | ✅ PASS |
| `TEST-CORE-IOC-ENRICH-001` | `basic_ioc_enrichment_workflow` | `TRIAGE_IRP_RUBRIC` | **95.0** / 100.0 | 0.0043s | ✅ PASS |
| `TEST-CORE-ENDPOINT-001` | `endpoint_triage_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0028s | ✅ PASS |
| `TEST-CORE-CONTAINMENT-001` | `ioc_containment_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0031s | ✅ PASS |
| `TEST-CORE-CASE-REPORT-001` | `case_report_workflow` | `REPORTING_RUBRIC` | **95.0** / 100.0 | 0.0040s | ✅ PASS |
| `TEST-CORE-ALERT-REPORT-001` | `alert_report_workflow` | `REPORTING_RUBRIC` | **100.0** / 100.0 | 0.0052s | ✅ PASS |
| `TEST-CORE-COMPROMISED-USER-001` | `compromised_user_irp_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0036s | ✅ PASS |
| `TEST-CORE-DETECTION-RULE-001` | `detection_rule_validation_workflow` | `DETECTION_ENGINEERING_RUBRIC` | **100.0** / 100.0 | 0.0063s | ✅ PASS |

---

## 2. Detailed Feedback & Category Breakdown

### `TEST-CORE-SUSP-LOGIN-001`: suspicious_login_workflow
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

### `TEST-CORE-SUSP-LOGIN-002`: suspicious_login_workflow
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

### `TEST-CORE-MALWARE-001`: malware_triage_workflow
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

### `TEST-CORE-IOC-ENRICH-001`: basic_ioc_enrichment_workflow
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

### `TEST-CORE-ENDPOINT-001`: endpoint_triage_workflow
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

### `TEST-CORE-CONTAINMENT-001`: ioc_containment_workflow
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

### `TEST-CORE-CASE-REPORT-001`: case_report_workflow
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

### `TEST-CORE-ALERT-REPORT-001`: alert_report_workflow
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

### `TEST-CORE-COMPROMISED-USER-001`: compromised_user_irp_workflow
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

### `TEST-CORE-DETECTION-RULE-001`: detection_rule_validation_workflow
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
