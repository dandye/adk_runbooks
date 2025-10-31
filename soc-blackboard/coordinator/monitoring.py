"""
Real-time Monitoring Module for SOC Blackboard Coordinator

Provides live monitoring capabilities for investigations in progress.
"""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict


@dataclass
class InvestigationStatus:
    """Current status of an investigation"""
    investigation_id: str
    case_id: str
    status: str  # active, completed, failed
    phase: str  # initialization, investigation, correlation, reporting
    active_agents: List[str]
    total_findings: int
    last_activity: str
    started_at: str
    blackboard_file: Optional[str] = None
    research_log_file: Optional[str] = None


class MonitoringDashboard:
    """
    Real-time monitoring dashboard for SOC investigations.
    Tracks active investigations, agent activities, and findings.
    """

    def __init__(self, update_interval: int = 5):
        self.update_interval = update_interval
        self.investigations = {}  # investigation_id -> InvestigationStatus
        self.callbacks = []  # List of callback functions for updates
        self.running = False
        self.lock = asyncio.Lock()

    async def register_investigation(self, investigation_id: str, case_id: str, 
                                   blackboard_file: str, research_log_file: str):
        """Register a new investigation for monitoring."""
        async with self.lock:
            status = InvestigationStatus(
                investigation_id=investigation_id,
                case_id=case_id,
                status="active",
                phase="initialization",
                active_agents=[],
                total_findings=0,
                last_activity=datetime.now(timezone.utc).isoformat(),
                started_at=datetime.now(timezone.utc).isoformat(),
                blackboard_file=blackboard_file,
                research_log_file=research_log_file
            )
            self.investigations[investigation_id] = status
            await self._notify_callbacks("investigation_registered", status)

    async def update_investigation_phase(self, investigation_id: str, phase: str):
        """Update the current phase of an investigation."""
        async with self.lock:
            if investigation_id in self.investigations:
                self.investigations[investigation_id].phase = phase
                self.investigations[investigation_id].last_activity = datetime.now(timezone.utc).isoformat()
                await self._notify_callbacks("phase_updated", self.investigations[investigation_id])

    async def update_active_agents(self, investigation_id: str, agents: List[str]):
        """Update the list of currently active agents."""
        async with self.lock:
            if investigation_id in self.investigations:
                self.investigations[investigation_id].active_agents = agents.copy()
                self.investigations[investigation_id].last_activity = datetime.now(timezone.utc).isoformat()
                await self._notify_callbacks("agents_updated", self.investigations[investigation_id])

    async def update_findings_count(self, investigation_id: str, count: int):
        """Update the total findings count."""
        async with self.lock:
            if investigation_id in self.investigations:
                self.investigations[investigation_id].total_findings = count
                self.investigations[investigation_id].last_activity = datetime.now(timezone.utc).isoformat()
                await self._notify_callbacks("findings_updated", self.investigations[investigation_id])

    async def complete_investigation(self, investigation_id: str, status: str = "completed"):
        """Mark an investigation as completed or failed."""
        async with self.lock:
            if investigation_id in self.investigations:
                self.investigations[investigation_id].status = status
                self.investigations[investigation_id].active_agents = []
                self.investigations[investigation_id].last_activity = datetime.now(timezone.utc).isoformat()
                await self._notify_callbacks("investigation_completed", self.investigations[investigation_id])

    async def get_investigation_status(self, investigation_id: str) -> Optional[InvestigationStatus]:
        """Get current status of a specific investigation."""
        async with self.lock:
            return self.investigations.get(investigation_id)

    async def get_all_investigations(self) -> List[InvestigationStatus]:
        """Get status of all investigations."""
        async with self.lock:
            return list(self.investigations.values())

    async def get_active_investigations(self) -> List[InvestigationStatus]:
        """Get only active investigations."""
        async with self.lock:
            return [inv for inv in self.investigations.values() if inv.status == "active"]

    def add_callback(self, callback: Callable):
        """Add a callback function to be notified of updates."""
        self.callbacks.append(callback)

    def remove_callback(self, callback: Callable):
        """Remove a callback function."""
        if callback in self.callbacks:
            self.callbacks.remove(callback)

    async def _notify_callbacks(self, event_type: str, data: InvestigationStatus):
        """Notify all registered callbacks of an update."""
        for callback in self.callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(event_type, data)
                else:
                    callback(event_type, data)
            except Exception as e:
                print(f"Error in monitoring callback: {e}")

    async def start_monitoring(self):
        """Start the monitoring loop."""
        self.running = True
        while self.running:
            await self._refresh_investigation_data()
            await asyncio.sleep(self.update_interval)

    async def stop_monitoring(self):
        """Stop the monitoring loop."""
        self.running = False

    async def _refresh_investigation_data(self):
        """Refresh investigation data from files."""
        async with self.lock:
            for investigation_id, status in self.investigations.items():
                if status.status != "active":
                    continue
                
                # Try to read blackboard file for findings count
                if status.blackboard_file and Path(status.blackboard_file).exists():
                    try:
                        with open(status.blackboard_file, 'r') as f:
                            data = json.load(f)
                        
                        total_findings = 0
                        knowledge_areas = data.get("knowledge_areas", {})
                        for area, findings in knowledge_areas.items():
                            if area in ["risk_scores", "investigation_metadata"]:
                                continue
                            if isinstance(findings, list):
                                total_findings += len(findings)
                        
                        if total_findings != status.total_findings:
                            old_count = status.total_findings
                            status.total_findings = total_findings
                            print(f"MONITOR: Investigation {investigation_id} findings updated: {old_count} -> {total_findings}")
                            
                    except Exception as e:
                        print(f"Error reading blackboard file: {e}")
                
                # Try to read research log for active agents
                if status.research_log_file and Path(status.research_log_file).exists():
                    try:
                        active_agents = set()
                        with open(status.research_log_file, 'r') as f:
                            for line in f:
                                if line.strip():
                                    activity = json.loads(line)
                                    if activity.get("status") in ["started", "in_progress"]:
                                        active_agents.add(activity.get("agent_name", "unknown"))
                        
                        new_active_agents = list(active_agents)
                        if new_active_agents != status.active_agents:
                            old_agents = status.active_agents.copy()
                            status.active_agents = new_active_agents
                            print(f"MONITOR: Investigation {investigation_id} active agents updated: {old_agents} -> {new_active_agents}")
                            
                    except Exception as e:
                        print(f"Error reading research log file: {e}")

    async def export_status_report(self, output_file: str = None) -> str:
        """Export a comprehensive status report."""
        if not output_file:
            output_file = f"monitoring_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        async with self.lock:
            report = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_investigations": len(self.investigations),
                "active_investigations": len([inv for inv in self.investigations.values() if inv.status == "active"]),
                "completed_investigations": len([inv for inv in self.investigations.values() if inv.status == "completed"]),
                "failed_investigations": len([inv for inv in self.investigations.values() if inv.status == "failed"]),
                "investigations": [asdict(inv) for inv in self.investigations.values()]
            }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return output_file

    async def get_investigation_summary(self) -> Dict[str, Any]:
        """Get a summary of all investigations."""
        async with self.lock:
            active = [inv for inv in self.investigations.values() if inv.status == "active"]
            completed = [inv for inv in self.investigations.values() if inv.status == "completed"]
            failed = [inv for inv in self.investigations.values() if inv.status == "failed"]
            
            all_agents = set()
            total_findings = 0
            for inv in self.investigations.values():
                all_agents.update(inv.active_agents)
                total_findings += inv.total_findings
            
            return {
                "total_investigations": len(self.investigations),
                "active_investigations": len(active),
                "completed_investigations": len(completed),
                "failed_investigations": len(failed),
                "success_rate": len(completed) / len(self.investigations) if self.investigations else 0,
                "total_findings_across_all": total_findings,
                "unique_agents_involved": list(all_agents),
                "active_investigation_details": [
                    {
                        "investigation_id": inv.investigation_id,
                        "case_id": inv.case_id,
                        "phase": inv.phase,
                        "active_agents": inv.active_agents,
                        "findings": inv.total_findings,
                        "runtime_minutes": self._calculate_runtime_minutes(inv.started_at)
                    } for inv in active
                ]
            }

    def _calculate_runtime_minutes(self, started_at: str) -> float:
        """Calculate runtime in minutes."""
        try:
            start_dt = datetime.fromisoformat(started_at.replace('Z', '+00:00'))
            now_dt = datetime.now(timezone.utc)
            return (now_dt - start_dt).total_seconds() / 60
        except:
            return 0.0


# Global monitoring dashboard instance
monitoring_dashboard = MonitoringDashboard()


def print_monitoring_callback(event_type: str, data: InvestigationStatus):
    """Simple callback that prints monitoring updates to console."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    if event_type == "investigation_registered":
        print(f"[{timestamp}] MONITOR: New investigation {data.case_id} registered")
    elif event_type == "phase_updated":
        print(f"[{timestamp}] MONITOR: Investigation {data.case_id} entered phase: {data.phase}")
    elif event_type == "agents_updated":
        agents_str = ", ".join(data.active_agents) if data.active_agents else "none"
        print(f"[{timestamp}] MONITOR: Investigation {data.case_id} active agents: {agents_str}")
    elif event_type == "findings_updated":
        print(f"[{timestamp}] MONITOR: Investigation {data.case_id} findings count: {data.total_findings}")
    elif event_type == "investigation_completed":
        print(f"[{timestamp}] MONITOR: Investigation {data.case_id} completed with status: {data.status}")


# Add the default console callback
monitoring_dashboard.add_callback(print_monitoring_callback)