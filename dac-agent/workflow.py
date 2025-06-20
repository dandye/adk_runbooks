"""
Detection-as-Code Rule Tuning Workflow Implementation

This module contains the autonomous workflow execution logic for the DAC agent,
implementing the steps outlined in detection_as_code_rule_tuning.md.
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import yaml

logger = logging.getLogger(__name__)


class DACWorkflowExecutor:
    """Executes the Detection-as-Code rule tuning workflow autonomously."""
    
    def __init__(self, agent_tools):
        """Initialize the workflow executor with agent tools.
        
        Args:
            agent_tools: Tuple of initialized MCP toolsets and custom tools
        """
        self.soar_toolset = agent_tools[0]
        self.siem_toolset = agent_tools[1] 
        self.gti_toolset = agent_tools[2]
        self.get_current_time = agent_tools[3]
        self.write_report = agent_tools[4]
        self.git_create_branch = agent_tools[5]
        self.git_commit_changes = agent_tools[6]
        self.git_push_branch = agent_tools[7]
        self.create_github_pr = agent_tools[8]
        self.validate_yaml_file = agent_tools[9]
        self.find_rule_files = agent_tools[10]
    
    async def execute_full_workflow(self) -> Dict:
        """Execute the complete DAC workflow autonomously.
        
        Returns:
            Dict: Summary of workflow execution results
        """
        logger.info("Starting Detection-as-Code rule tuning workflow")
        workflow_results = {
            "start_time": self.get_current_time()["current_time"],
            "cases_processed": 0,
            "rules_tuned": 0,
            "prs_created": 0,
            "errors": []
        }
        
        try:
            # Step 1: Monitor SOAR cases for tuning opportunities
            tuning_cases = await self._monitor_soar_cases()
            workflow_results["cases_found"] = len(tuning_cases)
            
            if not tuning_cases:
                logger.info("No cases requiring rule tuning found")
                return workflow_results
            
            # Process each case
            for case in tuning_cases:
                try:
                    case_result = await self._process_tuning_case(case)
                    workflow_results["cases_processed"] += 1
                    
                    if case_result.get("rule_tuned"):
                        workflow_results["rules_tuned"] += 1
                    
                    if case_result.get("pr_created"):
                        workflow_results["prs_created"] += 1
                        
                except Exception as e:
                    logger.error(f"Error processing case {case.get('id', 'unknown')}: {e}")
                    workflow_results["errors"].append(f"Case {case.get('id')}: {str(e)}")
            
            # Generate summary report
            await self._generate_workflow_report(workflow_results)
            
        except Exception as e:
            logger.error(f"Workflow execution failed: {e}")
            workflow_results["errors"].append(f"Workflow failure: {str(e)}")
        
        workflow_results["end_time"] = self.get_current_time()["current_time"]
        return workflow_results
    
    async def _monitor_soar_cases(self) -> List[Dict]:
        """Monitor SOAR cases for tuning opportunities.
        
        Returns:
            List[Dict]: Cases that indicate rule tuning is needed
        """
        logger.info("Monitoring SOAR cases for tuning opportunities")
        
        # Search criteria for cases requiring tuning
        search_criteria = {
            "status": "closed",
            "root_cause": ["normal_behavior", "false_positive", "authorized_activity"],
            "has_analyst_comments": True,
            "time_range": "last_7_days"
        }
        
        # Use SOAR MCP server to search for relevant cases
        try:
            # This would use the actual SOAR toolset methods
            # For now, returning sample data structure
            tuning_cases = [
                {
                    "id": "4232",
                    "rule_name": "Remote Monitoring Management Tools Execution",
                    "analyst_comment": "This case was a false positive. User jack.torrance is authorized to execute ScreenConnect in our environment. Rule should be tuned to exclude events where user.name = 'jack.torrance' AND host.name = 'desktop-7xl2kp3'.",
                    "host_name": "desktop-7xl2kp3",
                    "user_name": "jack.torrance",
                    "process_name": "ScreenConnect.exe",
                    "exclusion_type": "user_host_combination"
                }
            ]
            
            logger.info(f"Found {len(tuning_cases)} cases requiring rule tuning")
            return tuning_cases
            
        except Exception as e:
            logger.error(f"Failed to search SOAR cases: {e}")
            return []
    
    async def _process_tuning_case(self, case: Dict) -> Dict:
        """Process a single SOAR case for rule tuning.
        
        Args:
            case: SOAR case data containing tuning requirements
            
        Returns:
            Dict: Results of processing this case
        """
        case_id = case.get("id", "unknown")
        logger.info(f"Processing tuning case {case_id}")
        
        result = {
            "case_id": case_id,
            "rule_tuned": False,
            "pr_created": False,
            "error": None
        }
        
        try:
            # Step 2: Extract tuning requirements
            tuning_requirements = self._extract_tuning_requirements(case)
            
            # Step 3: Locate rule files
            rule_files = await self._locate_rule_files(tuning_requirements)
            
            if not rule_files:
                result["error"] = f"No rule files found for: {tuning_requirements.get('rule_pattern')}"
                return result
            
            # Step 4: Generate rule modifications
            for rule_file in rule_files:
                modification_result = await self._generate_rule_modification(
                    rule_file, tuning_requirements
                )
                
                if modification_result["success"]:
                    # Step 5: Create branch and commit changes
                    git_result = await self._create_git_workflow(
                        rule_file, case, modification_result
                    )
                    
                    if git_result["success"]:
                        result["rule_tuned"] = True
                        result["pr_created"] = git_result.get("pr_created", False)
                    else:
                        result["error"] = git_result.get("error")
                
        except Exception as e:
            logger.error(f"Error processing case {case_id}: {e}")
            result["error"] = str(e)
        
        return result
    
    def _extract_tuning_requirements(self, case: Dict) -> Dict:
        """Extract tuning requirements from SOAR case analyst comments.
        
        Args:
            case: SOAR case data
            
        Returns:
            Dict: Structured tuning requirements
        """
        comment = case.get("analyst_comment", "")
        
        # Parse analyst comment for tuning instructions
        requirements = {
            "rule_pattern": case.get("rule_name", ""),
            "exclusion_type": case.get("exclusion_type", "general"),
            "conditions": []
        }
        
        # Extract specific conditions from comment
        if case.get("user_name"):
            requirements["conditions"].append({
                "field": "user.name",
                "operator": "=",
                "value": case["user_name"]
            })
        
        if case.get("host_name"):
            requirements["conditions"].append({
                "field": "host.name", 
                "operator": "=",
                "value": case["host_name"]
            })
        
        if case.get("process_name"):
            requirements["conditions"].append({
                "field": "process.name",
                "operator": "=", 
                "value": case["process_name"]
            })
        
        logger.info(f"Extracted tuning requirements: {requirements}")
        return requirements
    
    async def _locate_rule_files(self, requirements: Dict) -> List[str]:
        """Locate rule files that match the tuning requirements.
        
        Args:
            requirements: Tuning requirements extracted from case
            
        Returns:
            List[str]: Paths to matching rule files
        """
        rule_pattern = requirements.get("rule_pattern", "")
        
        # Search for rule files
        search_result = self.find_rule_files(rule_pattern)
        
        if search_result["success"] and search_result["count"] > 0:
            rule_files = [match["file_path"] for match in search_result["matches"]]
            logger.info(f"Found {len(rule_files)} matching rule files")
            return rule_files
        else:
            logger.warning(f"No rule files found for pattern: {rule_pattern}")
            return []
    
    async def _generate_rule_modification(self, rule_file_path: str, requirements: Dict) -> Dict:
        """Generate rule modifications based on tuning requirements.
        
        Args:
            rule_file_path: Path to the rule file to modify
            requirements: Tuning requirements
            
        Returns:
            Dict: Result of rule modification
        """
        logger.info(f"Generating rule modification for: {rule_file_path}")
        
        try:
            # Read current rule file
            with open(rule_file_path, 'r') as f:
                rule_data = yaml.safe_load(f)
            
            # Generate exclusion logic based on requirements
            exclusion_conditions = []
            for condition in requirements.get("conditions", []):
                exclusion_conditions.append(
                    f"{condition['field']} {condition['operator']} \"{condition['value']}\""
                )
            
            if exclusion_conditions:
                # Add NOT clause to existing query
                current_query = rule_data.get("logic", {}).get("query", "")
                exclusion_clause = " AND ".join(exclusion_conditions)
                
                # Insert NOT clause into query
                if "NOT (" in current_query:
                    # Add to existing NOT clause
                    modified_query = current_query.replace(
                        "NOT (",
                        f"NOT (\n      ({exclusion_clause}) OR\n      ("
                    ) + "\n    )"
                else:
                    # Add new NOT clause
                    modified_query = f"{current_query} AND\n    NOT ({exclusion_clause})"
                
                rule_data["logic"]["query"] = modified_query
                
                # Update metadata
                rule_data["metadata"]["last_modified"] = datetime.now().strftime("%Y-%m-%d")
                if "version" in rule_data["metadata"]:
                    version_parts = rule_data["metadata"]["version"].split(".")
                    if len(version_parts) >= 2:
                        minor_version = int(version_parts[1]) + 1
                        rule_data["metadata"]["version"] = f"{version_parts[0]}.{minor_version}"
            
            # Validate YAML syntax
            validation_result = self.validate_yaml_file(rule_file_path)
            if not validation_result["valid"]:
                return {
                    "success": False,
                    "error": f"YAML validation failed: {validation_result['error']}"
                }
            
            # Write modified rule back to file
            with open(rule_file_path, 'w') as f:
                yaml.dump(rule_data, f, default_flow_style=False, indent=2)
            
            return {
                "success": True,
                "modified_file": rule_file_path,
                "exclusion_added": exclusion_clause if exclusion_conditions else None
            }
            
        except Exception as e:
            logger.error(f"Failed to modify rule file {rule_file_path}: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _create_git_workflow(self, rule_file_path: str, case: Dict, modification_result: Dict) -> Dict:
        """Create Git branch, commit changes, and create pull request.
        
        Args:
            rule_file_path: Path to modified rule file
            case: Original SOAR case data
            modification_result: Result of rule modification
            
        Returns:
            Dict: Result of Git workflow operations
        """
        case_id = case.get("id", "unknown")
        rule_name = case.get("rule_name", "rule").lower().replace(" ", "-")
        branch_name = f"tune/{rule_name}-case-{case_id}"
        
        logger.info(f"Creating Git workflow for branch: {branch_name}")
        
        try:
            # Create feature branch
            branch_result = self.git_create_branch(branch_name)
            if not branch_result["success"]:
                return {
                    "success": False,
                    "error": f"Failed to create branch: {branch_result['error']}"
                }
            
            # Commit changes
            commit_message = self._generate_commit_message(case, modification_result)
            commit_result = self.git_commit_changes([rule_file_path], commit_message)
            if not commit_result["success"]:
                return {
                    "success": False,
                    "error": f"Failed to commit changes: {commit_result['error']}"
                }
            
            # Push branch
            push_result = self.git_push_branch(branch_name)
            if not push_result["success"]:
                return {
                    "success": False,
                    "error": f"Failed to push branch: {push_result['error']}"
                }
            
            # Create pull request
            pr_title, pr_body = self._generate_pr_content(case, modification_result)
            pr_result = self.create_github_pr(pr_title, pr_body)
            
            return {
                "success": True,
                "branch_name": branch_name,
                "pr_created": pr_result["success"],
                "pr_url": pr_result.get("pr_url") if pr_result["success"] else None,
                "error": pr_result.get("error") if not pr_result["success"] else None
            }
            
        except Exception as e:
            logger.error(f"Git workflow failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _generate_commit_message(self, case: Dict, modification_result: Dict) -> str:
        """Generate descriptive commit message for rule tuning.
        
        Args:
            case: SOAR case data
            modification_result: Rule modification details
            
        Returns:
            str: Formatted commit message
        """
        case_id = case.get("id", "unknown")
        rule_name = case.get("rule_name", "Detection Rule")
        
        message = f"Tune {rule_name} based on case #{case_id} feedback\n\n"
        
        if case.get("user_name") and case.get("host_name"):
            message += f"- Added exclusion for authorized user: {case['user_name']}\n"
            message += f"- Excluded host: {case['host_name']}\n"
        
        message += f"- Reduces false positives for legitimate operations\n"
        message += f"- SOAR case: #{case_id}\n"
        
        if case.get("analyst_comment"):
            message += f"\nAnalyst feedback:\n{case['analyst_comment'][:200]}..."
        
        return message
    
    def _generate_pr_content(self, case: Dict, modification_result: Dict) -> Tuple[str, str]:
        """Generate pull request title and body.
        
        Args:
            case: SOAR case data
            modification_result: Rule modification details
            
        Returns:
            Tuple[str, str]: PR title and body
        """
        case_id = case.get("id", "unknown")
        rule_name = case.get("rule_name", "Detection Rule")
        
        title = f"Tune {rule_name} - Case #{case_id} False Positive"
        
        body = f"""## Summary
- Tunes detection rule based on SOAR case #{case_id} analyst feedback
- Adds exclusion for authorized user/host combination
- Reduces false positives while maintaining detection effectiveness

## SOAR Case Details
- **Case ID**: #{case_id}
- **Rule**: {rule_name}
- **Root Cause**: {case.get('exclusion_type', 'false_positive')}

## Changes Made
- Added exclusion conditions to rule logic
- Updated rule metadata and version
- Preserved existing detection capabilities

## Security Review Checklist
- [ ] Exclusion doesn't create detection blind spots
- [ ] Tuning is specific to the false positive pattern  
- [ ] No overly broad exclusions applied
- [ ] Maintains detection for actual threats
- [ ] Includes proper documentation

## Test Plan
- [ ] Rule syntax validation passed
- [ ] Logic review completed
- [ ] Historical impact assessment
- [ ] False positive verification

## Analyst Feedback
```
{case.get('analyst_comment', 'No additional comments')}
```

## Expected Impact
- Reduction in false positive alerts
- Improved analyst efficiency
- Maintained security coverage

---
*This PR was generated automatically by the DAC Agent based on SOAR case analysis.*
"""
        
        return title, body
    
    async def _generate_workflow_report(self, results: Dict) -> None:
        """Generate a summary report of the workflow execution.
        
        Args:
            results: Workflow execution results
        """
        timestamp = self.get_current_time()["current_time"]
        report_name = f"DAC_Workflow_Report_{timestamp}"
        
        report_content = f"""# Detection-as-Code Workflow Execution Report

**Generated**: {timestamp}

## Summary
- **Cases Found**: {results.get('cases_found', 0)}
- **Cases Processed**: {results.get('cases_processed', 0)}
- **Rules Tuned**: {results.get('rules_tuned', 0)}
- **Pull Requests Created**: {results.get('prs_created', 0)}

## Execution Timeline
- **Start Time**: {results.get('start_time', 'Unknown')}
- **End Time**: {results.get('end_time', 'Unknown')}

## Errors Encountered
"""
        
        if results.get("errors"):
            for error in results["errors"]:
                report_content += f"- {error}\n"
        else:
            report_content += "No errors encountered during workflow execution.\n"
        
        report_content += f"""

## Next Steps
1. Monitor pull request review and approval process
2. Track CI/CD pipeline execution for deployed rules
3. Analyze post-deployment false positive metrics
4. Update rule tuning effectiveness statistics

---
*Report generated automatically by DAC Agent*
"""
        
        self.write_report(report_name, report_content)
        logger.info(f"Workflow report generated: {report_name}")