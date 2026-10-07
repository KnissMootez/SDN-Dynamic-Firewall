#!/usr/bin/env python3
"""
NAC Dashboard Server
Flask API + WebSocket server for real-time NAC monitoring

Run: python3 dashboard_server.py
Access: http://localhost:5000
"""

from flask import Flask, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import json
import os
import time
from threading import Thread

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('NAC_SECRET_KEY', 'change-me')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# File paths
STATE_FILE = '/tmp/nac_state.json'
TOPOLOGY_FILE = '/tmp/topology.json'
AI_METRICS_FILE = '/tmp/ai_metrics.json'
ATTACK_LOG_FILE = '/tmp/attack_log.json'
MININET_CMD_FILE = '/tmp/mininet_commands.json'

def read_json_file(filepath, default=None):
    """Safely read JSON file"""
    if not os.path.exists(filepath):
        return default if default is not None else {}
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except:
        return default if default is not None else {}

def write_json_file(filepath, data):
    """Safely write JSON file"""
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except:
        return False

# ============================================================================
# REST API ENDPOINTS
# ============================================================================

@app.route('/')
def index():
    """Serve dashboard HTML"""
    try:
        with open('dashboard.html', 'r') as f:
            content = f.read()
        return content
    except FileNotFoundError:
        return "Error: dashboard.html not found. Make sure it's in the same directory as dashboard_server.py", 404

@app.route('/api/topology')
def get_topology():
    """Get network topology"""
    return jsonify(read_json_file(TOPOLOGY_FILE, {'switches': [], 'hosts': [], 'links': []}))

@app.route('/api/hosts')
def get_hosts():
    """Get all hosts with their states"""
    return jsonify(read_json_file(STATE_FILE))

@app.route('/api/ai_metrics')
def get_ai_metrics():
    """Get AI risk scores"""
    return jsonify(read_json_file(AI_METRICS_FILE))

@app.route('/api/attacks')
def get_attacks():
    """Get recent attacks"""
    return jsonify(read_json_file(ATTACK_LOG_FILE, []))

@app.route('/api/flows')
def get_flows():
    """Get OpenFlow flow tables"""
    return jsonify(read_json_file('/tmp/flow_tables.json', {}))

@app.route('/api/approve/<mac>', methods=['POST'])
def approve_host(mac):
    """Approve a host"""
    success = write_json_file(MININET_CMD_FILE, {
        'action': 'approve',
        'mac': mac
    })
    return jsonify({'success': success, 'message': f'Approval sent for {mac}'})

@app.route('/api/block/<mac>', methods=['POST'])
def block_host(mac):
    """Block a host"""
    success = write_json_file(MININET_CMD_FILE, {
        'action': 'block',
        'mac': mac
    })
    return jsonify({'success': success, 'message': f'Block sent for {mac}'})

@app.route('/api/add_host', methods=['POST'])
def add_host():
    """Add a new guest host"""
    data = request.json
    hostname = data.get('hostname', 'guest')
    switch = data.get('switch', 's7')
    
    success = write_json_file(MININET_CMD_FILE, {
        'action': 'add_guest',
        'hostname': hostname,
        'switch': switch
    })
    return jsonify({'success': success, 'message': f'Adding {hostname} to {switch}'})

@app.route('/api/simulate_attack', methods=['POST'])
def simulate_attack():
    """Simulate an attack"""
    data = request.json
    attack_type = data.get('type', 'port_scan')
    hostname = data.get('hostname')
    target = data.get('target', '192.168.1.20')
    
    cmd = {
        'hostname': hostname,
        'target': target
    }
    
    if attack_type == 'port_scan':
        cmd['action'] = 'simulate_port_scan'
    elif attack_type == 'ddos':
        cmd['action'] = 'simulate_ddos'
        cmd['duration'] = data.get('duration', 5)
    elif attack_type == 'arp_spoof':
        cmd['action'] = 'simulate_arp_spoof'
        cmd['fake_ip'] = data.get('fake_ip', '192.168.1.1')
    else:
        return jsonify({'success': False, 'message': 'Unknown attack type'})
    
    success = write_json_file(MININET_CMD_FILE, cmd)
    return jsonify({'success': success, 'message': f'Simulating {attack_type} from {hostname}'})

# ============================================================================
# WEBSOCKET - Real-time updates
# ============================================================================

def background_update():
    """Send updates to clients every 2 seconds"""
    while True:
        time.sleep(2)  # Update every 2 seconds
        try:
            data = {
                'topology': read_json_file(TOPOLOGY_FILE, {'switches': [], 'hosts': [], 'links': []}),
                'hosts': read_json_file(STATE_FILE),
                'ai_metrics': read_json_file(AI_METRICS_FILE),
                'attacks': read_json_file(ATTACK_LOG_FILE, [])[-10:],  # Last 10 attacks
                'flows': read_json_file('/tmp/flow_tables.json', {})
            }
            socketio.emit('update', data, namespace='/')
            print(f"📤 Update sent: {len(data['topology']['hosts'])} hosts")  # Debug log
        except Exception as e:
            print(f"❌ Update error: {e}")

@socketio.on('connect')
def handle_connect():
    """Client connected"""
    print('✅ Client connected!')
    # Send initial data
    data = {
        'topology': read_json_file(TOPOLOGY_FILE, {'switches': [], 'hosts': [], 'links': []}),
        'hosts': read_json_file(STATE_FILE),
        'ai_metrics': read_json_file(AI_METRICS_FILE),
        'attacks': read_json_file(ATTACK_LOG_FILE, [])[-10:],
        'flows': read_json_file('/tmp/flow_tables.json', {})
    }
    print(f'📤 Sending initial data: {len(data["topology"]["switches"])} switches, {len(data["topology"]["hosts"])} hosts')
    emit('update', data)

@socketio.on('disconnect')
def handle_disconnect():
    """Client disconnected"""
    print('Client disconnected')

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("NAC DASHBOARD SERVER")
    print("=" * 70)
    print("Starting Flask server on http://localhost:5001")
    print("Access dashboard at: http://localhost:5001")
    print("=" * 70)
    
    # Start background update thread
    update_thread = Thread(target=background_update, daemon=True)
    update_thread.start()
    
    # Run Flask app
    socketio.run(app, host='0.0.0.0', port=5001, debug=False)
