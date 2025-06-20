"""
Core knowledge store implementation for the SOC Blackboard system.
Provides a shared knowledge space where all agents can read and write findings.
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class Finding:
    """Represents a single finding written to the blackboard"""
    id: str
    timestamp: str
    agent: str
    area: str
    finding: Dict[str, Any]
    confidence: str
    tags: List[str]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class InvestigationBlackboard:
    """
    Central knowledge store for SOC investigations using the Blackboard pattern.
    Multiple agents can read from and write to this shared knowledge space.
    """

    def __init__(self, investigation_id: str, case_context: Optional[Dict[str, Any]] = None):
        self.investigation_id = investigation_id
        self.created_at = datetime.now(timezone.utc)
        self.case_context = case_context or {}
        self.lock = asyncio.Lock()
        
        # Initialize knowledge areas
        self.knowledge_areas = {
            "network_analysis": [],
            "endpoint_behaviors": [],
            "log_correlations": [],
            "ioc_enrichments": [],
            "timeline_events": [],
            "threat_intelligence": [],
            "risk_scores": {},
            "investigation_metadata": {
                "investigation_id": investigation_id,
                "created_at": self.created_at.isoformat(),
                "status": "active",
                "case_context": self.case_context
            }
        }
        
        # Track subscribers for real-time updates
        self.subscribers = {}
        
    async def write(self, area: str, finding: Dict[str, Any], agent_name: str, 
                   confidence: str = "medium", tags: Optional[List[str]] = None) -> str:
        """
        Write a finding to the specified knowledge area.
        
        Args:
            area: Knowledge area to write to
            finding: The finding data
            agent_name: Name of the agent writing the finding
            confidence: Confidence level (low, medium, high)
            tags: Optional tags for categorization
            
        Returns:
            str: Unique ID of the created finding
        """
        if area not in self.knowledge_areas:
            raise ValueError(f"Unknown knowledge area: {area}")
            
        finding_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        
        finding_obj = Finding(
            id=finding_id,
            timestamp=timestamp,
            agent=agent_name,
            area=area,
            finding=finding,
            confidence=confidence,
            tags=tags or [],
            metadata={"created_by": agent_name}
        )
        
        async with self.lock:
            if area == "risk_scores":
                # Risk scores are stored as a dict, not a list
                self.knowledge_areas[area].update(finding)
            elif area == "investigation_metadata":
                # Investigation metadata is also a dict
                self.knowledge_areas[area].update(finding)
            else:
                # Ensure the area exists and is a list
                if area not in self.knowledge_areas:
                    self.knowledge_areas[area] = []
                elif not isinstance(self.knowledge_areas[area], list):
                    print(f"Warning: Knowledge area '{area}' is not a list, converting...")
                    self.knowledge_areas[area] = []
                self.knowledge_areas[area].append(finding_obj.to_dict())
            
            # Update investigation metadata
            self.knowledge_areas["investigation_metadata"]["last_updated"] = timestamp
        
        # Notify subscribers
        await self._notify_subscribers(area, finding_obj)
        
        return finding_id
    
    async def read(self, area: Optional[str] = None, 
                  filters: Optional[Dict[str, Any]] = None) -> Union[List[Dict], Dict]:
        """
        Read findings from the blackboard.
        
        Args:
            area: Specific knowledge area to read (None for all)
            filters: Optional filters to apply
            
        Returns:
            Findings from the specified area or entire blackboard
        """
        async with self.lock:
            if area:
                if area not in self.knowledge_areas:
                    raise ValueError(f"Unknown knowledge area: {area}")
                data = self.knowledge_areas[area]
            else:
                data = self.knowledge_areas.copy()
        
        if filters:
            data = self._apply_filters(data, filters)
            
        return data
    
    async def query(self, filters: Dict[str, Any]) -> List[Dict]:
        """
        Advanced querying with complex filters.
        
        Args:
            filters: Query filters
            
        Returns:
            Filtered findings
        """
        results = []
        
        async with self.lock:
            for area, findings in self.knowledge_areas.items():
                if area in ["risk_scores", "investigation_metadata"]:
                    continue
                    
                if isinstance(findings, list):
                    filtered = self._apply_filters(findings, filters)
                    results.extend(filtered)
        
        return results
    
    async def get_timeline(self) -> List[Dict]:
        """
        Get chronological view of all findings.
        
        Returns:
            All findings sorted by timestamp
        """
        timeline = []
        
        async with self.lock:
            for area, findings in self.knowledge_areas.items():
                if area in ["risk_scores", "investigation_metadata"]:
                    continue
                    
                if isinstance(findings, list):
                    timeline.extend(findings)
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x.get("timestamp", ""))
        
        return timeline
    
    async def export(self, format: str = "json") -> Union[str, Dict]:
        """
        Export investigation data.
        
        Args:
            format: Export format (json, dict)
            
        Returns:
            Exported data
        """
        async with self.lock:
            data = {
                "investigation_id": self.investigation_id,
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "knowledge_areas": self.knowledge_areas.copy()
            }
        
        if format == "json":
            return json.dumps(data, indent=2)
        else:
            return data
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the current investigation."""
        stats = {
            "investigation_id": self.investigation_id,
            "created_at": self.created_at.isoformat(),
            "total_findings": 0,
            "findings_by_area": {},
            "findings_by_agent": {},
            "confidence_distribution": {"low": 0, "medium": 0, "high": 0}
        }
        
        async with self.lock:
            for area, findings in self.knowledge_areas.items():
                if area in ["risk_scores", "investigation_metadata"]:
                    continue
                    
                if isinstance(findings, list):
                    area_count = len(findings)
                    stats["findings_by_area"][area] = area_count
                    stats["total_findings"] += area_count
                    
                    for finding in findings:
                        agent = finding.get("agent", "unknown")
                        stats["findings_by_agent"][agent] = stats["findings_by_agent"].get(agent, 0) + 1
                        
                        confidence = finding.get("confidence", "medium")
                        if confidence in stats["confidence_distribution"]:
                            stats["confidence_distribution"][confidence] += 1
        
        return stats
    
    def _apply_filters(self, data: Union[List[Dict], Dict], filters: Dict[str, Any]) -> Union[List[Dict], Dict]:
        """Apply filters to data."""
        if isinstance(data, dict):
            return data
            
        filtered = []
        for item in data:
            if self._matches_filters(item, filters):
                filtered.append(item)
        
        return filtered
    
    def _matches_filters(self, item: Dict[str, Any], filters: Dict[str, Any]) -> bool:
        """Check if an item matches the given filters."""
        for key, value in filters.items():
            if key == "area" and item.get("area") != value:
                return False
            elif key == "confidence" and item.get("confidence") != value:
                return False
            elif key == "agent" and item.get("agent") != value:
                return False
            elif key == "tags" and not any(tag in item.get("tags", []) for tag in value):
                return False
            elif key == "timerange":
                item_time = item.get("timestamp", "")
                if not self._in_time_range(item_time, value):
                    return False
        
        return True
    
    def _in_time_range(self, timestamp: str, timerange: Dict[str, Any]) -> bool:
        """Check if timestamp is in the specified range."""
        try:
            item_dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            if "start" in timerange:
                start_dt = datetime.fromisoformat(timerange["start"].replace('Z', '+00:00'))
                if item_dt < start_dt:
                    return False
                    
            if "end" in timerange:
                end_dt = datetime.fromisoformat(timerange["end"].replace('Z', '+00:00'))
                if item_dt > end_dt:
                    return False
                    
            return True
        except:
            return False
    
    async def subscribe(self, area: str, callback):
        """Subscribe to updates for a specific area."""
        if area not in self.subscribers:
            self.subscribers[area] = []
        self.subscribers[area].append(callback)
    
    async def _notify_subscribers(self, area: str, finding: Finding):
        """Notify subscribers of new findings."""
        if area in self.subscribers:
            for callback in self.subscribers[area]:
                try:
                    await callback(finding)
                except Exception as e:
                    # Log error but don't fail the write operation
                    print(f"Error notifying subscriber: {e}")
    
    async def close(self):
        """Clean up resources."""
        self.subscribers.clear()
        
        # Update investigation status
        async with self.lock:
            self.knowledge_areas["investigation_metadata"]["status"] = "completed"
            self.knowledge_areas["investigation_metadata"]["completed_at"] = datetime.now(timezone.utc).isoformat()


class BlackboardManager:
    """Manages multiple investigation blackboards."""
    
    def __init__(self):
        self.active_investigations = {}
        self.lock = asyncio.Lock()
    
    async def create_investigation(self, investigation_id: str, 
                                 case_context: Optional[Dict[str, Any]] = None) -> InvestigationBlackboard:
        """Create a new investigation blackboard."""
        async with self.lock:
            if investigation_id in self.active_investigations:
                raise ValueError(f"Investigation {investigation_id} already exists")
            
            blackboard = InvestigationBlackboard(investigation_id, case_context)
            self.active_investigations[investigation_id] = blackboard
            
            return blackboard
    
    async def get_investigation(self, investigation_id: str) -> Optional[InvestigationBlackboard]:
        """Get an existing investigation blackboard."""
        async with self.lock:
            return self.active_investigations.get(investigation_id)
    
    async def close_investigation(self, investigation_id: str):
        """Close and remove an investigation."""
        async with self.lock:
            if investigation_id in self.active_investigations:
                await self.active_investigations[investigation_id].close()
                del self.active_investigations[investigation_id]
    
    async def list_active_investigations(self) -> List[str]:
        """List all active investigation IDs."""
        async with self.lock:
            return list(self.active_investigations.keys())