"""
Web interface for the SOC Blackboard Monitoring Dashboard
"""

from flask import Flask, render_template, jsonify, Response
import json
import asyncio
import queue
from datetime import datetime
from pathlib import Path
import threading

# Import the global monitoring dashboard instance
from .monitoring import monitoring_dashboard

app = Flask(__name__)

# Store SSE clients
sse_clients = []
sse_clients_lock = threading.Lock()

def monitoring_web_callback(event_type: str, data):
    """Callback to send updates to SSE clients."""
    message = {
        'type': event_type,
        'data': data.__dict__ if hasattr(data, '__dict__') else data,
        'timestamp': datetime.now().isoformat()
    }
    
    # Send to all SSE clients
    with sse_clients_lock:
        dead_clients = []
        for client_queue in sse_clients:
            try:
                client_queue.put(json.dumps(message))
            except:
                dead_clients.append(client_queue)
        
        # Clean up dead clients
        for client in dead_clients:
            sse_clients.remove(client)

# Register our callback
monitoring_dashboard.add_callback(monitoring_web_callback)

@app.route('/')
def dashboard():
    """Main dashboard view."""
    return render_template('dashboard.html')

@app.route('/investigation/<investigation_id>')
def investigation_detail(investigation_id):
    """Detailed view of a specific investigation."""
    return render_template('investigation.html', investigation_id=investigation_id)

@app.route('/api/investigations')
def get_investigations():
    """Get all investigations with current status."""
    # Run async function in sync context
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        summary = loop.run_until_complete(monitoring_dashboard.get_investigation_summary())
        all_investigations = loop.run_until_complete(monitoring_dashboard.get_all_investigations())
        
        return jsonify({
            'summary': summary,
            'investigations': [inv.__dict__ for inv in all_investigations]
        })
    finally:
        loop.close()

@app.route('/api/investigations/<investigation_id>')
def get_investigation_detail(investigation_id):
    """Get detailed information about a specific investigation."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        status = loop.run_until_complete(monitoring_dashboard.get_investigation_status(investigation_id))
        if not status:
            return jsonify({'error': 'Investigation not found'}), 404
        
        return jsonify({
            'investigation': status.__dict__,
            'blackboard_exists': Path(status.blackboard_file).exists() if status.blackboard_file else False,
            'log_exists': Path(status.research_log_file).exists() if status.research_log_file else False
        })
    finally:
        loop.close()

@app.route('/api/investigations/<investigation_id>/activities')
def get_investigation_activities(investigation_id):
    """Get detailed activities for an investigation."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        status = loop.run_until_complete(monitoring_dashboard.get_investigation_status(investigation_id))
        if not status or not status.research_log_file:
            return jsonify({'error': 'Investigation not found'}), 404
        
        activities = []
        try:
            with open(status.research_log_file, 'r') as f:
                for line in f:
                    if line.strip():
                        activities.append(json.loads(line))
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        
        # Generate Gantt data
        gantt_data = []
        for activity in activities:
            if activity.get('start_time'):
                gantt_data.append({
                    'agent': activity['agent_name'],
                    'task': activity['task_type'],
                    'description': activity['description'],
                    'start': activity['start_time'],
                    'end': activity.get('end_time', datetime.now().isoformat()),
                    'status': activity['status'],
                    'duration': activity.get('duration_seconds', 0)
                })
        
        return jsonify({
            'investigation_id': investigation_id,
            'total_activities': len(activities),
            'activities': activities,
            'gantt_data': gantt_data
        })
    finally:
        loop.close()

@app.route('/api/investigations/<investigation_id>/blackboard')
def get_blackboard_summary(investigation_id):
    """Get blackboard summary for an investigation."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        status = loop.run_until_complete(monitoring_dashboard.get_investigation_status(investigation_id))
        if not status or not status.blackboard_file:
            return jsonify({'error': 'Blackboard data not found'}), 404
        
        if not Path(status.blackboard_file).exists():
            return jsonify({'error': 'Blackboard file not found'}), 404
        
        try:
            with open(status.blackboard_file, 'r') as f:
                blackboard_data = json.load(f)
            
            # Extract summary information
            knowledge_areas = blackboard_data.get('knowledge_areas', {})
            findings_by_area = {}
            
            for area, data in knowledge_areas.items():
                if isinstance(data, list):
                    findings_by_area[area] = len(data)
                elif isinstance(data, dict):
                    # Handle nested structures
                    findings_by_area[area] = len(data)
            
            return jsonify({
                'investigation_id': investigation_id,
                'created_at': blackboard_data.get('created_at'),
                'saved_at': blackboard_data.get('saved_at'),
                'findings_by_area': findings_by_area,
                'total_findings': sum(findings_by_area.values()),
                'risk_scores': knowledge_areas.get('risk_scores', {}),
                'investigation_metadata': knowledge_areas.get('investigation_metadata', {})
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    finally:
        loop.close()

@app.route('/api/stream')
def stream():
    """Server-Sent Events endpoint."""
    def generate():
        client_queue = queue.Queue()
        
        with sse_clients_lock:
            sse_clients.append(client_queue)
        
        try:
            # Send initial state
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                initial_data = loop.run_until_complete(monitoring_dashboard.get_investigation_summary())
                all_investigations = loop.run_until_complete(monitoring_dashboard.get_all_investigations())
                initial_message = {
                    'type': 'initial',
                    'data': {
                        'summary': initial_data,
                        'investigations': [inv.__dict__ for inv in all_investigations]
                    }
                }
                yield f"data: {json.dumps(initial_message)}\n\n"
            finally:
                loop.close()
            
            while True:
                # Wait for updates
                try:
                    message = client_queue.get(timeout=30)
                    yield f"data: {message}\n\n"
                except queue.Empty:
                    # Send keepalive
                    yield "data: {\"type\": \"keepalive\"}\n\n"
        finally:
            with sse_clients_lock:
                if client_queue in sse_clients:
                    sse_clients.remove(client_queue)
    
    return Response(generate(), mimetype="text/event-stream", headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no'  # Disable Nginx buffering
    })

def run_web_interface(host='0.0.0.0', port=5000, debug=False):
    """Run the web interface."""
    print(f"Starting SOC Investigation Monitor at http://{host}:{port}")
    app.run(host=host, port=port, debug=debug, threaded=True, use_reloader=False)

# Create a function to start the web interface in a thread
def start_web_monitor_thread(host='0.0.0.0', port=5000):
    """Start the web monitor in a background thread."""
    web_thread = threading.Thread(
        target=run_web_interface,
        kwargs={'host': host, 'port': port, 'debug': False},
        daemon=True
    )
    web_thread.start()
    return web_thread