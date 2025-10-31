# SOC Investigation Web Monitor

A real-time web interface for monitoring SOC investigations powered by the Blackboard Coordinator.

## Features

- **Live Dashboard**: Real-time view of all active investigations
- **Investigation Timeline**: Gantt chart visualization of agent activities
- **Activity Stream**: Live feed of investigation events
- **Agent Performance**: Track agent utilization and task completion
- **Blackboard Integration**: View findings and risk scores

## Quick Start

### Option 1: Enable Web Monitor with ADK (Recommended)

1. Set environment variables:
```bash
cd soc-blackboard
source .env.webmonitor  # Enables web monitoring
```

2. Run investigations as normal:
```bash
echo "start an investigation for soar case 3052" | adk run coordinator
```

3. Open http://localhost:5000 to see live updates!

### Option 2: Run Standalone Monitor

If you just want to monitor existing investigations without running new ones:

```bash
cd soc-blackboard
python test_web_monitor.py
```

Then open http://localhost:5000 in your browser.

### Option 3: Manual Environment Variables

Set these before running `adk run coordinator`:
```bash
export SOC_WEB_MONITOR=true
export SOC_WEB_PORT=5000
echo "start an investigation for soar case 3052" | adk run coordinator
```

## Web Interface Overview

### Dashboard View
- **Summary Bar**: Active investigations, success rate, total findings
- **Investigation Cards**: Live status of each investigation
  - Current phase (initialization → investigation → correlation → reporting)
  - Active agents with real-time updates
  - Running timer showing investigation duration
  - Findings count
- **Activity Feed**: Real-time stream of investigation events

### Investigation Detail View
Access by clicking on any investigation card:

1. **Timeline Tab**: Interactive Gantt chart showing:
   - Agent activities over time
   - Task durations
   - Parallel execution visualization

2. **Activities Tab**: Detailed list of all activities
   - Filter by agent or status
   - View task descriptions and durations
   - See success/failure status

3. **Blackboard Tab**: Investigation findings
   - Findings grouped by knowledge area
   - Risk scores
   - Investigation metadata

## Technical Details

### Architecture
- Built on the existing `MonitoringDashboard` class
- Uses Flask for the web server
- Server-Sent Events (SSE) for real-time updates
- No additional dependencies (uses existing monitoring callbacks)

### API Endpoints
- `GET /` - Main dashboard
- `GET /investigation/<id>` - Investigation details
- `GET /api/investigations` - All investigations data
- `GET /api/investigations/<id>/activities` - Investigation activities
- `GET /api/investigations/<id>/blackboard` - Blackboard data
- `GET /api/stream` - SSE endpoint for real-time updates

### Real-Time Updates
The web interface receives updates through the monitoring callback system:
- `investigation_registered` - New investigation started
- `phase_updated` - Investigation phase changed
- `agents_updated` - Active agents changed
- `findings_updated` - New findings added
- `investigation_completed` - Investigation finished

## Customization

### Change Port
```python
coordinator = BlackboardCoordinator(start_web_monitor=True, web_port=8080)
```

### Custom Callbacks
Add your own monitoring callbacks:
```python
def my_callback(event_type, data):
    print(f"Event: {event_type}, Data: {data}")

monitoring_dashboard.add_callback(my_callback)
```

## Troubleshooting

### Port Already in Use
If port 5000 is already in use, change the port:
```python
coordinator = BlackboardCoordinator(start_web_monitor=True, web_port=5001)
```

### No Updates Showing
1. Check that investigations are actually running
2. Verify the SSE connection in browser console
3. Ensure monitoring_dashboard callbacks are registered

### Can't Access Web Interface
1. Check firewall settings for port 5000
2. Try accessing via `http://127.0.0.1:5000` instead of localhost
3. Ensure Flask is installed: `pip install flask`

## Future Enhancements

- Authentication and access control
- Investigation comparison views
- Export investigation reports
- Historical investigation archive
- Custom dashboard layouts
- Alert notifications for failures

## Integration with ADK

The web monitor is fully integrated with the ADK coordinator workflow:
1. Coordinator updates `monitoring_dashboard` throughout investigation
2. Web interface receives callbacks for all state changes
3. No additional configuration needed - just enable and go!