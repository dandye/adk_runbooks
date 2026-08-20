# ADK Workflow Benchmark (expanded_cases_alerts)

**Generated:** 2026-08-20T21:31:44.307474+00:00  
**Total Evaluated:** 25 | **Passed:** 25 | **Failed:** 0 | **Pass Rate:** 100.0%  
**Average Score:** 90.6 / 100.0 | **Average Latency:** 0.0042s | **Total Tokens:** ~27,617 (Avg ~1105/test)

---

## 1. Summary Scorecard Table

| Test ID | Workflow Name | Rubric Profile | Score | Duration | Est. Tokens (In / Out / Total) | Status |
|:---|:---|:---:|:---:|:---:|:---:|:---:|
| `TEST-EXP-MALWARE-IRP-33279` | `malware_irp_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0141s | 764 / 245 / **1009** | ✅ PASS |
| `TEST-EXP-PHISHING-IRP-33285` | `phishing_irp_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0164s | 767 / 275 / **1042** | ✅ PASS |
| `TEST-EXP-RANSOMWARE-IRP-33286` | `ransomware_irp_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0038s | 748 / 212 / **960** | ✅ PASS |
| `TEST-EXP-COMPROMISED-USER-33284` | `compromised_user_irp_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0031s | 744 / 209 / **953** | ✅ PASS |
| `TEST-EXP-ALERT-REPORT-AVOSLOCKER` | `alert_report_workflow` | `REPORTING_RUBRIC` | **100.0** / 100.0 | 0.0035s | 851 / 2246 / **3097** | ✅ PASS |
| `TEST-EXP-CASE-REPORT-LOKIBOT` | `case_report_workflow` | `REPORTING_RUBRIC` | **95.0** / 100.0 | 0.0040s | 738 / 412 / **1150** | ✅ PASS |
| `TEST-EXP-INVESTIGATION-REPORT-01` | `create_investigation_report_workflow` | `REPORTING_RUBRIC` | **95.0** / 100.0 | 0.0046s | 734 / 518 / **1252** | ✅ PASS |
| `TEST-EXP-SUSPICIOUS-LOGIN-HIGH` | `suspicious_login_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0038s | 991 / 306 / **1297** | ✅ PASS |
| `TEST-EXP-MALWARE-TRIAGE-01` | `malware_triage_workflow` | `TRIAGE_IRP_RUBRIC` | **100.0** / 100.0 | 0.0030s | 867 / 416 / **1283** | ✅ PASS |
| `TEST-EXP-ENDPOINT-TRIAGE-ISOLATE` | `endpoint_triage_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0028s | 870 / 328 / **1198** | ✅ PASS |
| `TEST-EXP-IOC-CONTAINMENT-IP` | `ioc_containment_workflow` | `TRIAGE_IRP_RUBRIC` | **93.0** / 100.0 | 0.0033s | 745 / 280 / **1025** | ✅ PASS |
| `TEST-EXP-BASIC-IOC-ENRICH` | `basic_ioc_enrichment_workflow` | `TRIAGE_IRP_RUBRIC` | **95.0** / 100.0 | 0.0047s | 982 / 286 / **1268** | ✅ PASS |
| `TEST-EXP-TRIAGE-ALERTS-01` | `triage_alerts_workflow` | `TRIAGE_IRP_RUBRIC` | **88.0** / 100.0 | 0.0025s | 734 / 137 / **871** | ✅ PASS |
| `TEST-EXP-LATERAL-MOVE-HUNT-01` | `lateral_movement_hunt_workflow` | `THREAT_HUNTING_RUBRIC` | **83.0** / 100.0 | 0.0030s | 732 / 94 / **826** | ✅ PASS |
| `TEST-EXP-CREDENTIAL-HUNT-01` | `credential_access_hunt_workflow` | `THREAT_HUNTING_RUBRIC` | **83.0** / 100.0 | 0.0025s | 735 / 98 / **833** | ✅ PASS |
| `TEST-EXP-ADVANCED-HUNT-01` | `advanced_threat_hunting_workflow` | `THREAT_HUNTING_RUBRIC` | **88.0** / 100.0 | 0.0027s | 746 / 167 / **913** | ✅ PASS |
| `TEST-EXP-APT-THREAT-HUNT-01` | `apt_threat_hunt_workflow` | `THREAT_HUNTING_RUBRIC` | **83.0** / 100.0 | 0.0022s | 855 / 142 / **997** | ✅ PASS |
| `TEST-EXP-PROACTIVE-GTI-HUNT-01` | `proactive_gti_threat_hunt_workflow` | `THREAT_HUNTING_RUBRIC` | **83.0** / 100.0 | 0.0026s | 731 / 131 / **862** | ✅ PASS |
| `TEST-EXP-IOC-THREAT-HUNT-01` | `ioc_threat_hunt_workflow` | `THREAT_HUNTING_RUBRIC` | **90.0** / 100.0 | 0.0024s | 736 / 163 / **899** | ✅ PASS |
| `TEST-EXP-CLOSE-DUPLICATES-01` | `close_duplicate_cases_workflow` | `TRIAGE_IRP_RUBRIC` | **88.0** / 100.0 | 0.0052s | 741 / 134 / **875** | ✅ PASS |
| `TEST-EXP-GROUP-CASES-V2-01` | `group_cases_v2_workflow` | `TRIAGE_IRP_RUBRIC` | **88.0** / 100.0 | 0.0027s | 730 / 144 / **874** | ✅ PASS |
| `TEST-EXP-TIMELINE-PROCESS-01` | `timeline_process_analysis_workflow` | `REPORTING_RUBRIC` | **85.0** / 100.0 | 0.0025s | 732 / 102 / **834** | ✅ PASS |
| `TEST-EXP-UEBA-EXFIL-01` | `ueba_report_workflow` | `REPORTING_RUBRIC` | **90.0** / 100.0 | 0.0031s | 737 / 161 / **898** | ✅ PASS |
| `TEST-EXP-DETECTION-RULE-VAL-01` | `detection_rule_validation_workflow` | `DETECTION_ENGINEERING_RUBRIC` | **100.0** / 100.0 | 0.0044s | 745 / 786 / **1531** | ✅ PASS |
| `TEST-EXP-DETECTION-REPORT-01` | `detection_report_workflow` | `REPORTING_RUBRIC` | **80.0** / 100.0 | 0.0028s | 733 / 137 / **870** | ✅ PASS |

---

## 2. Detailed Feedback & Category Breakdown

### `TEST-EXP-MALWARE-IRP-33279`: malware_irp_workflow
* **Verdict:** PASS (Score: 93.0/100.0)
* **Run Time:** 0.0141s
* **Token Usage:** ~1009 tokens (Input: ~764, Output: ~245)
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

### `TEST-EXP-PHISHING-IRP-33285`: phishing_irp_workflow
* **Verdict:** PASS (Score: 93.0/100.0)
* **Run Time:** 0.0164s
* **Token Usage:** ~1042 tokens (Input: ~767, Output: ~275)
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

### `TEST-EXP-RANSOMWARE-IRP-33286`: ransomware_irp_workflow
* **Verdict:** PASS (Score: 93.0/100.0)
* **Run Time:** 0.0038s
* **Token Usage:** ~960 tokens (Input: ~748, Output: ~212)
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

### `TEST-EXP-COMPROMISED-USER-33284`: compromised_user_irp_workflow
* **Verdict:** PASS (Score: 93.0/100.0)
* **Run Time:** 0.0031s
* **Token Usage:** ~953 tokens (Input: ~744, Output: ~209)
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

### `TEST-EXP-ALERT-REPORT-AVOSLOCKER`: alert_report_workflow
* **Verdict:** PASS (Score: 100.0/100.0)
* **Run Time:** 0.0035s
* **Token Usage:** ~3097 tokens (Input: ~851, Output: ~2246)
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

### `TEST-EXP-CASE-REPORT-LOKIBOT`: case_report_workflow
* **Verdict:** PASS (Score: 95.0/100.0)
* **Run Time:** 0.0040s
* **Token Usage:** ~1150 tokens (Input: ~738, Output: ~412)
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

### `TEST-EXP-INVESTIGATION-REPORT-01`: create_investigation_report_workflow
* **Verdict:** PASS (Score: 95.0/100.0)
* **Run Time:** 0.0046s
* **Token Usage:** ~1252 tokens (Input: ~734, Output: ~518)
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

### `TEST-EXP-SUSPICIOUS-LOGIN-HIGH`: suspicious_login_workflow
* **Verdict:** PASS (Score: 93.0/100.0)
* **Run Time:** 0.0038s
* **Token Usage:** ~1297 tokens (Input: ~991, Output: ~306)
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

### `TEST-EXP-MALWARE-TRIAGE-01`: malware_triage_workflow
* **Verdict:** PASS (Score: 100.0/100.0)
* **Run Time:** 0.0030s
* **Token Usage:** ~1283 tokens (Input: ~867, Output: ~416)
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

### `TEST-EXP-ENDPOINT-TRIAGE-ISOLATE`: endpoint_triage_workflow
* **Verdict:** PASS (Score: 93.0/100.0)
* **Run Time:** 0.0028s
* **Token Usage:** ~1198 tokens (Input: ~870, Output: ~328)
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

### `TEST-EXP-IOC-CONTAINMENT-IP`: ioc_containment_workflow
* **Verdict:** PASS (Score: 93.0/100.0)
* **Run Time:** 0.0033s
* **Token Usage:** ~1025 tokens (Input: ~745, Output: ~280)
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

### `TEST-EXP-BASIC-IOC-ENRICH`: basic_ioc_enrichment_workflow
* **Verdict:** PASS (Score: 95.0/100.0)
* **Run Time:** 0.0047s
* **Token Usage:** ~1268 tokens (Input: ~982, Output: ~286)
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

### `TEST-EXP-TRIAGE-ALERTS-01`: triage_alerts_workflow
* **Verdict:** PASS (Score: 88.0/100.0)
* **Run Time:** 0.0025s
* **Token Usage:** ~871 tokens (Input: ~734, Output: ~137)
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

### `TEST-EXP-LATERAL-MOVE-HUNT-01`: lateral_movement_hunt_workflow
* **Verdict:** PASS (Score: 83.0/100.0)
* **Run Time:** 0.0030s
* **Token Usage:** ~826 tokens (Input: ~732, Output: ~94)
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

### `TEST-EXP-CREDENTIAL-HUNT-01`: credential_access_hunt_workflow
* **Verdict:** PASS (Score: 83.0/100.0)
* **Run Time:** 0.0025s
* **Token Usage:** ~833 tokens (Input: ~735, Output: ~98)
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

### `TEST-EXP-ADVANCED-HUNT-01`: advanced_threat_hunting_workflow
* **Verdict:** PASS (Score: 88.0/100.0)
* **Run Time:** 0.0027s
* **Token Usage:** ~913 tokens (Input: ~746, Output: ~167)
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

### `TEST-EXP-APT-THREAT-HUNT-01`: apt_threat_hunt_workflow
* **Verdict:** PASS (Score: 83.0/100.0)
* **Run Time:** 0.0022s
* **Token Usage:** ~997 tokens (Input: ~855, Output: ~142)
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

### `TEST-EXP-PROACTIVE-GTI-HUNT-01`: proactive_gti_threat_hunt_workflow
* **Verdict:** PASS (Score: 83.0/100.0)
* **Run Time:** 0.0026s
* **Token Usage:** ~862 tokens (Input: ~731, Output: ~131)
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

### `TEST-EXP-IOC-THREAT-HUNT-01`: ioc_threat_hunt_workflow
* **Verdict:** PASS (Score: 90.0/100.0)
* **Run Time:** 0.0024s
* **Token Usage:** ~899 tokens (Input: ~736, Output: ~163)
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

### `TEST-EXP-CLOSE-DUPLICATES-01`: close_duplicate_cases_workflow
* **Verdict:** PASS (Score: 88.0/100.0)
* **Run Time:** 0.0052s
* **Token Usage:** ~875 tokens (Input: ~741, Output: ~134)
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

### `TEST-EXP-GROUP-CASES-V2-01`: group_cases_v2_workflow
* **Verdict:** PASS (Score: 88.0/100.0)
* **Run Time:** 0.0027s
* **Token Usage:** ~874 tokens (Input: ~730, Output: ~144)
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

### `TEST-EXP-TIMELINE-PROCESS-01`: timeline_process_analysis_workflow
* **Verdict:** PASS (Score: 85.0/100.0)
* **Run Time:** 0.0025s
* **Token Usage:** ~834 tokens (Input: ~732, Output: ~102)
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

### `TEST-EXP-UEBA-EXFIL-01`: ueba_report_workflow
* **Verdict:** PASS (Score: 90.0/100.0)
* **Run Time:** 0.0031s
* **Token Usage:** ~898 tokens (Input: ~737, Output: ~161)
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

### `TEST-EXP-DETECTION-RULE-VAL-01`: detection_rule_validation_workflow
* **Verdict:** PASS (Score: 100.0/100.0)
* **Run Time:** 0.0044s
* **Token Usage:** ~1531 tokens (Input: ~745, Output: ~786)
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

### `TEST-EXP-DETECTION-REPORT-01`: detection_report_workflow
* **Verdict:** PASS (Score: 80.0/100.0)
* **Run Time:** 0.0028s
* **Token Usage:** ~870 tokens (Input: ~733, Output: ~137)
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
