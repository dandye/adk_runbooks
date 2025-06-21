"""
Research Log Module for SOC Blackboard Coordinator

Provides real-time logging of agent activities and task tracking.
"""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict


@dataclass
class AgentActivity:
    """Represents a single agent activity/task"""
    activity_id: str
    timestamp: str
    agent_name: str
    investigation_id: str
    task_type: str
    status: str  # started, in_progress, completed, failed
    description: str
    metadata: Dict[str, Any]
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_seconds: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ResearchLog:
    """
    Tracks agent activities and tasks in real-time for investigation monitoring.
    Provides visibility into what each agent is doing throughout the investigation.
    """

    def __init__(self, investigation_id: str, output_dir: str = "logs"):
        self.investigation_id = investigation_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.log_file = self.output_dir / f"research_log_{investigation_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
        self.activities = {}  # activity_id -> AgentActivity
        self.active_tasks = {}  # agent_name -> current_activity_id
        self.lock = asyncio.Lock()

    async def start_task(self, agent_name: str, task_type: str, description: str, 
                        metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Log the start of an agent task.
        
        Args:
            agent_name: Name of the agent starting the task
            task_type: Type of task (investigation, correlation, report_generation, etc.)
            description: Human-readable description of the task
            metadata: Additional metadata about the task
            
        Returns:
            activity_id: Unique identifier for this activity
        """
        import uuid
        
        activity_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        
        activity = AgentActivity(
            activity_id=activity_id,
            timestamp=timestamp,
            agent_name=agent_name,
            investigation_id=self.investigation_id,
            task_type=task_type,
            status="started",
            description=description,
            metadata=metadata or {},
            start_time=timestamp
        )
        
        async with self.lock:
            self.activities[activity_id] = activity
            self.active_tasks[agent_name] = activity_id
            
            # Write to log file immediately
            await self._write_to_file(activity)
            
        print(f"RESEARCH_LOG: [{agent_name}] STARTED {task_type}: {description}")
        return activity_id

    async def update_task(self, activity_id: str, status: str, metadata: Optional[Dict[str, Any]] = None):
        """
        Update an existing task with new status or metadata.
        
        Args:
            activity_id: ID of the activity to update
            status: New status (in_progress, completed, failed)
            metadata: Additional metadata to merge
        """
        async with self.lock:
            if activity_id in self.activities:
                activity = self.activities[activity_id]
                activity.status = status
                activity.timestamp = datetime.now(timezone.utc).isoformat()
                
                if status in ["completed", "failed"]:
                    activity.end_time = activity.timestamp
                    if activity.start_time:
                        try:
                            start_dt = datetime.fromisoformat(activity.start_time.replace('Z', '+00:00'))
                            end_dt = datetime.fromisoformat(activity.end_time.replace('Z', '+00:00'))
                            activity.duration_seconds = (end_dt - start_dt).total_seconds()
                        except:
                            pass
                    
                    # Remove from active tasks
                    if activity.agent_name in self.active_tasks and self.active_tasks[activity.agent_name] == activity_id:
                        del self.active_tasks[activity.agent_name]
                
                if metadata:
                    activity.metadata.update(metadata)
                
                # Write updated activity to log file
                await self._write_to_file(activity)
                
                status_emoji = {"completed": "✓", "failed": "✗", "in_progress": "⋯"}.get(status, "•")
                print(f"RESEARCH_LOG: [{activity.agent_name}] {status_emoji} {status.upper()} {activity.task_type}: {activity.description}")

    async def complete_task(self, activity_id: str, metadata: Optional[Dict[str, Any]] = None):
        """Mark a task as completed."""
        await self.update_task(activity_id, "completed", metadata)

    async def fail_task(self, activity_id: str, error: str, metadata: Optional[Dict[str, Any]] = None):
        """Mark a task as failed with error information."""
        error_metadata = {"error": error}
        if metadata:
            error_metadata.update(metadata)
        await self.update_task(activity_id, "failed", error_metadata)

    async def get_active_tasks(self) -> Dict[str, AgentActivity]:
        """Get all currently active tasks by agent."""
        async with self.lock:
            active = {}
            for agent_name, activity_id in self.active_tasks.items():
                if activity_id in self.activities:
                    active[agent_name] = self.activities[activity_id]
            return active

    async def get_task_history(self, agent_name: Optional[str] = None) -> List[AgentActivity]:
        """Get task history, optionally filtered by agent."""
        async with self.lock:
            activities = list(self.activities.values())
            if agent_name:
                activities = [a for a in activities if a.agent_name == agent_name]
            
            # Sort by timestamp
            activities.sort(key=lambda x: x.timestamp)
            return activities

    async def get_investigation_summary(self) -> Dict[str, Any]:
        """Get a summary of all investigation activities."""
        async with self.lock:
            activities = list(self.activities.values())
            
        total_tasks = len(activities)
        completed_tasks = len([a for a in activities if a.status == "completed"])
        failed_tasks = len([a for a in activities if a.status == "failed"])
        active_tasks = len([a for a in activities if a.status in ["started", "in_progress"]])
        
        agents_involved = set(a.agent_name for a in activities)
        task_types = {}
        for activity in activities:
            task_types[activity.task_type] = task_types.get(activity.task_type, 0) + 1
        
        # Calculate total investigation time
        start_times = [a.start_time for a in activities if a.start_time]
        end_times = [a.end_time for a in activities if a.end_time]
        
        total_duration = None
        if start_times and end_times:
            try:
                earliest_start = min(datetime.fromisoformat(t.replace('Z', '+00:00')) for t in start_times)
                latest_end = max(datetime.fromisoformat(t.replace('Z', '+00:00')) for t in end_times)
                total_duration = (latest_end - earliest_start).total_seconds()
            except:
                pass
        
        return {
            "investigation_id": self.investigation_id,
            "total_tasks": total_tasks,
            "completed_tasks": completed_tasks,
            "failed_tasks": failed_tasks,
            "active_tasks": active_tasks,
            "success_rate": completed_tasks / total_tasks if total_tasks > 0 else 0,
            "agents_involved": list(agents_involved),
            "task_types": task_types,
            "total_duration_seconds": total_duration,
            "log_file": str(self.log_file)
        }

    async def _write_to_file(self, activity: AgentActivity):
        """Write activity to the log file in JSONL format."""
        try:
            with open(self.log_file, 'a') as f:
                json.dump(activity.to_dict(), f)
                f.write('\n')
        except Exception as e:
            print(f"ERROR: Failed to write to research log file: {e}")

    async def export_html_report(self) -> str:
        """Export a nice HTML report of the research log."""
        activities = await self.get_task_history()
        summary = await self.get_investigation_summary()
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Research Log - Investigation {self.investigation_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .summary {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .activity {{ margin-bottom: 15px; padding: 10px; border-left: 4px solid #ccc; }}
        .completed {{ border-left-color: #28a745; }}
        .failed {{ border-left-color: #dc3545; }}
        .started {{ border-left-color: #007bff; }}
        .in_progress {{ border-left-color: #ffc107; }}
        .agent-name {{ font-weight: bold; color: #0056b3; }}
        .timestamp {{ color: #666; font-size: 0.9em; }}
        .task-type {{ background-color: #e9ecef; padding: 2px 6px; border-radius: 3px; font-size: 0.8em; }}
        .metadata {{ color: #666; font-size: 0.9em; margin-top: 5px; }}
    </style>
</head>
<body>
    <h1>Research Log - Investigation {self.investigation_id}</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Tasks:</strong> {summary['total_tasks']}</p>
        <p><strong>Completed:</strong> {summary['completed_tasks']} | <strong>Failed:</strong> {summary['failed_tasks']} | <strong>Active:</strong> {summary['active_tasks']}</p>
        <p><strong>Success Rate:</strong> {summary['success_rate']:.1%}</p>
        <p><strong>Agents Involved:</strong> {', '.join(summary['agents_involved'])}</p>
        <p><strong>Task Types:</strong> {', '.join(f"{k}({v})" for k, v in summary['task_types'].items())}</p>
        {f"<p><strong>Total Duration:</strong> {summary['total_duration_seconds']:.1f} seconds</p>" if summary['total_duration_seconds'] else ""}
    </div>
    
    <h2>Activity Timeline</h2>
"""
        
        for activity in activities:
            status_class = activity.status.replace(" ", "_")
            duration_text = ""
            if activity.duration_seconds:
                duration_text = f" ({activity.duration_seconds:.1f}s)"
            
            html_content += f"""
    <div class="activity {status_class}">
        <div class="agent-name">{activity.agent_name}</div>
        <div class="timestamp">{activity.timestamp}{duration_text}</div>
        <div class="task-type">{activity.task_type}</div>
        <div>{activity.description}</div>
"""
            if activity.metadata:
                html_content += f'        <div class="metadata">Metadata: {json.dumps(activity.metadata, indent=2)}</div>\n'
            html_content += "    </div>\n"
        
        html_content += """
</body>
</html>
"""
        
        html_file = self.log_file.with_suffix('.html')
        with open(html_file, 'w') as f:
            f.write(html_content)
        
        return str(html_file)


class ResearchLogManager:
    """Manages research logs for multiple investigations."""
    
    def __init__(self, output_dir: str = "logs"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.active_logs = {}  # investigation_id -> ResearchLog
        self.lock = asyncio.Lock()

    async def get_log(self, investigation_id: str) -> ResearchLog:
        """Get or create a research log for an investigation."""
        async with self.lock:
            if investigation_id not in self.active_logs:
                self.active_logs[investigation_id] = ResearchLog(investigation_id, str(self.output_dir))
            return self.active_logs[investigation_id]

    async def close_log(self, investigation_id: str):
        """Close and finalize a research log."""
        async with self.lock:
            if investigation_id in self.active_logs:
                log = self.active_logs[investigation_id]
                
                # Export final HTML report
                try:
                    html_file = await log.export_html_report()
                    print(f"Research log HTML report saved: {html_file}")
                except Exception as e:
                    print(f"Failed to export HTML report: {e}")
                
                del self.active_logs[investigation_id]