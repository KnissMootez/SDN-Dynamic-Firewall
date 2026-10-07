"""
Mininet Helper - Simple add_guest for Fixed NAC Controller
Works perfectly with the new controller's MAC learning

Usage:
  mininet> source mininet_helpers_simple.py
  mininet> add_guest('laptop1')
"""

import time
import sys
import json

def add_guest(hostname, switch='s7'):
    """Add a guest device - works with fixed controller"""
    # Get net from caller's frame
    try:
        frame = sys._getframe(1)
        _net = frame.f_globals.get('net') or frame.f_locals.get('net')
    except:
        _net = None
    
    if _net is None:
        print("Error: Could not find 'net'.")
        return None
    
    print(f"\n{'='*70}")
    print(f"ADDING GUEST: {hostname}")
    print(f"{'='*70}")
    
    # Get switch
    sw = _net.get(switch)
    if not sw:
        print(f"  ❌ Error: Switch {switch} not found!")
        return None
    
    print(f"  ✓ Target switch: {switch}")
    
    # Create host
    print(f"  ✓ Creating host...")
    host = _net.addHost(hostname, ip='0.0.0.0/24')
    
    # Add link
    print(f"  ✓ Creating link...")
    _net.addLink(host, sw)
    
    # CRITICAL: Find the actual port name and add to OVS bridge
    print(f"  ✓ Configuring OVS port...")
    import subprocess
    
    # Get all links and find the one for this host
    links_output = subprocess.check_output(['mn', '-c'], stderr=subprocess.DEVNULL, text=True, timeout=1) if False else ""
    
    # Find switch port by checking what was just created
    # The port will be s{X}-eth{Y} where Y is the next available port number
    import re
    existing_ports = sw.cmd(f'ovs-vsctl list-ports {switch}').strip().split('\n')
    
    # Find the highest port number
    max_port = 0
    for port in existing_ports:
        match = re.search(r'eth(\d+)', port)
        if match:
            max_port = max(max_port, int(match.group(1)))
    
    # The new port should be the next one
    new_port = f'{switch}-eth{max_port + 1}'
    
    # Add port to OVS bridge
    result = sw.cmd(f'ovs-vsctl add-port {switch} {new_port} 2>&1')
    if 'already exists' not in result and result.strip():
        print(f"     Port {new_port} added to bridge")
    else:
        print(f"     Using port {new_port}")
    
    # Bring up interface
    iface = f'{hostname}-eth0'
    host.cmd(f'ip link set {iface} up')
    time.sleep(1)
    
    # Get MAC
    mac = host.cmd(f'cat /sys/class/net/{iface}/address').strip()
    print(f"  ℹ️  MAC: {mac}")
    print(f"  ℹ️  Interface: {iface}")
    
    # Request DHCP
    print(f"\n  [DHCP] Requesting IP address...")
    print(f"  (This may take 10-15 seconds...)")
    
    # Clear old leases
    host.cmd('rm -rf /var/lib/dhcp/dhclient* 2>/dev/null')
    host.cmd('killall -9 dhclient 2>/dev/null')
    
    # Request DHCP
    host.cmd(f'dhclient -v {iface} > /tmp/dhclient_{hostname}.log 2>&1 &')
    
    # Wait and check
    for i in range(6):
        time.sleep(2)
        ip = host.cmd(f'ip -4 addr show {iface} | grep inet | awk \'{{print $2}}\'').strip()
        if ip:
            break
    
    print(f"\n{'='*70}")
    
    if ip:
        ip_clean = ip.split('/')[0]
        last_octet = int(ip_clean.split('.')[-1])
        
        print(f"✅ SUCCESS!")
        print(f"{'='*70}")
        print(f"  Hostname: {hostname}")
        print(f"  MAC:      {mac}")
        print(f"  IP:       {ip_clean}")
        print(f"  Switch:   {switch}")
        
        if 100 <= last_octet <= 149:
            print(f"  Range:    IoT (100-149)")
            print(f"  Status:   Will be AUTO-APPROVED")
        elif 150 <= last_octet <= 200:
            print(f"  Range:    Guest (150-200)")
            print(f"  Status:   QUARANTINED - needs approval")
            print(f"\n  To approve:")
            print(f"    python3 nac_admin.py approve {mac}")
            print(f"  Or in Mininet:")
            print(f"    mininet> py approve_guest('{hostname}')")
        else:
            print(f"  Range:    Unexpected ({last_octet})")
        
        # Test connectivity to gateway
        print(f"\n  Testing connectivity to gateway (192.168.1.35)...")
        ping_result = host.cmd('ping -c 2 -W 2 192.168.1.35')
        
        if '2 received' in ping_result or '1 received' in ping_result:
            print(f"  ✅ Gateway reachable (quarantine allows ping to gateway)")
        else:
            print(f"  ❌ Gateway NOT reachable")
            print(f"     This might indicate a network issue")
        
    else:
        print(f"❌ DHCP FAILED")
        print(f"{'='*70}")
        print(f"  Check logs: {hostname} cat /tmp/dhclient_{hostname}.log")
        print(f"  Or manually: {hostname} dhclient -v {iface}")
    
    print(f"{'='*70}\n")
    
    return host


def approve_guest(mac_or_hostname):
    import json
    """Approve a guest for network access"""
    try:
        frame = sys._getframe(1)
        _net = frame.f_globals.get('net') or frame.f_locals.get('net')
    except:
        _net = None
    
    if _net is None:
        print("Error: Could not find 'net'.")
        return False
    
    # Check if it's a hostname or MAC
    mac = mac_or_hostname
    if ':' not in mac_or_hostname:
        host = _net.get(mac_or_hostname)
        if not host:
            print(f"Error: Host {mac_or_hostname} not found!")
            return False
        iface = f'{mac_or_hostname}-eth0'
        mac = host.cmd(f'cat /sys/class/net/{iface}/address').strip()
    
    print(f"\n{'='*70}")
    print(f"APPROVING: {mac}")
    print(f"{'='*70}")
    
    command = {
        'command': 'approve',
        'mac': mac,
        'timestamp': time.time()
    }
    
    try:
        with open('/tmp/nac_command.json', 'w') as f:
            json.dump(command, f)
        
        print(f"  ✓ Sent approval to controller")
        time.sleep(2)
        print(f"  ✓ Check controller logs for confirmation")
        print(f"{'='*70}\n")
        return True
        
    except Exception as e:
        print(f"  ❌ Error: {e}")
        print(f"{'='*70}\n")
        return False


def block_guest(mac_or_hostname):
    """Block a guest from network access"""
    import json
    try:
        frame = sys._getframe(1)
        _net = frame.f_globals.get('net') or frame.f_locals.get('net')
    except:
        _net = None
    
    if _net is None:
        print("Error: Could not find 'net'.")
        return False
    
    # Check if it's a hostname or MAC
    mac = mac_or_hostname
    if ':' not in mac_or_hostname:
        host = _net.get(mac_or_hostname)
        if not host:
            print(f"Error: Host {mac_or_hostname} not found!")
            return False
        iface = f'{mac_or_hostname}-eth0'
        mac = host.cmd(f'cat /sys/class/net/{iface}/address').strip()
    
    print(f"\n{'='*70}")
    print(f"BLOCKING: {mac}")
    print(f"{'='*70}")
    
    command = {
        'command': 'block',
        'mac': mac,
        'timestamp': time.time()
    }
    
    try:
        with open('/tmp/nac_command.json', 'w') as f:
            json.dump(command, f)
        
        print(f"  ✓ Sent block to controller")
        time.sleep(2)
        print(f"  ✓ Host should now be blocked")
        print(f"{'='*70}\n")
        return True
        
    except Exception as e:
        print(f"  ❌ Error: {e}")
        print(f"{'='*70}\n")
        return False


def list_hosts():
    """List all hosts in the network"""
    try:
        frame = sys._getframe(1)
        _net = frame.f_globals.get('net') or frame.f_locals.get('net')
    except:
        _net = None
    
    if _net is None:
        print("Error: Could not find 'net'")
        return
    
    print(f"\n{'='*70}")
    print("NETWORK HOSTS")
    print(f"{'='*70}")
    print(f"{'Host':<15} | {'IP Address':<18} | {'MAC Address':<17}")
    print(f"{'-'*15}-+-{'-'*18}-+-{'-'*17}")
    
    for host in _net.hosts:
        iface = f'{host.name}-eth0'
        ip = host.cmd(f'ip -4 addr show {iface} 2>/dev/null | grep inet | awk \'{{print $2}}\'').strip()
        mac = host.cmd(f'cat /sys/class/net/{iface}/address 2>/dev/null').strip()
        
        if not ip:
            ip = "No IP"
        if not mac:
            mac = "No MAC"
        
        print(f"{host.name:<15} | {ip:<18} | {mac}")
    
    print(f"{'='*70}\n")


def test_connectivity(hostname):
    """Test connectivity from a host"""
    try:
        frame = sys._getframe(1)
        _net = frame.f_globals.get('net') or frame.f_locals.get('net')
    except:
        _net = None
    
    if _net is None:
        print("Error: Could not find 'net'")
        return
    
    host = _net.get(hostname)
    if not host:
        print(f"Error: Host {hostname} not found!")
        return
    
    print(f"\n{'='*70}")
    print(f"TESTING CONNECTIVITY FROM {hostname}")
    print(f"{'='*70}")
    
    targets = [
        ('Gateway', '192.168.1.35'),
        ('LAN (h1)', '192.168.1.10'),
        ('Web Server', '192.168.1.20'),
    ]
    
    for name, ip in targets:
        result = host.cmd(f'ping -c 1 -W 2 {ip}')
        if '1 received' in result:
            print(f"  ✅ {name:<20} ({ip})")
        else:
            print(f"  ❌ {name:<20} ({ip})")
    
    print(f"{'='*70}\n")


def remove_host(hostname):
    """Remove a host from the network"""
    try:
        frame = sys._getframe(1)
        _net = frame.f_globals.get('net') or frame.f_locals.get('net')
    except:
        _net = None
    
    if _net is None:
        print("Error: Could not find 'net'")
        return False
    
    host = _net.get(hostname)
    if not host:
        print(f"Error: Host {hostname} not found!")
        return False
    
    print(f"\n{'='*60}")
    print(f"Removing: {hostname}")
    
    # Stop processes
    host.cmd('killall dhclient 2>/dev/null')
    
    # Stop the host
    host.stop()
    
    # Remove from network
    if hostname in _net.nameToNode:
        del _net.nameToNode[hostname]
    if host in _net.hosts:
        _net.hosts.remove(host)
    
    print(f"  ✓ Removed")
    print(f"{'='*60}\n")
    return True
def simulate_port_scan(hostname, target_ip):
    """Simulate a port scan attack"""
    try:
        frame = sys._getframe(1)
        _net = frame.f_globals.get('net') or frame.f_locals.get('net')
    except:
        _net = None
    
    if _net is None:
        print("Error: Could not find 'net'")
        return
    
    host = _net.get(hostname)
    if not host:
        print(f"Error: Host {hostname} not found!")
        return
    
    print(f"\n{'='*70}")
    print(f"⚠️  SIMULATING PORT SCAN ATTACK")
    print(f"{'='*70}")
    print(f"  Attacker: {hostname}")
    print(f"  Target:   {target_ip}")
    print(f"  Method:   TCP connect scan on ports 20-50")
    print(f"\n  Scanning...")
    
    # Create a Python script to do the port scan
    scan_script = f'''
import socket
import sys

target = "{target_ip}"
for port in range(20, 51):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect((target, port))
        s.close()
    except:
        pass
    sys.stdout.flush()
'''
    
    # Write script and execute
    host.cmd('cat > /tmp/portscan.py << "EOF"\n' + scan_script + '\nEOF')
    host.cmd('python3 /tmp/portscan.py &')
    
    time.sleep(3)
    
    print(f"\n  ✅ Port scan completed!")
    print(f"  → Scanned ports 20-50 (31 ports)")
    print(f"  → Controller should detect >15 ports in 10 seconds")
    print(f"  → Check controller logs for attack detection")
    print(f"{'='*70}\n")


def simulate_ddos(hostname, target_ip, duration=10):
    """Simulate a DDoS/flood attack"""
    try:
        frame = sys._getframe(1)
        _net = frame.f_globals.get('net') or frame.f_locals.get('net')
    except:
        _net = None
    
    if _net is None:
        print("Error: Could not find 'net'")
        return
    
    host = _net.get(hostname)
    if not host:
        print(f"Error: Host {hostname} not found!")
        return
    
    print(f"\n{'='*70}")
    print(f"⚠️  SIMULATING DDoS/FLOOD ATTACK")
    print(f"{'='*70}")
    print(f"  Attacker: {hostname}")
    print(f"  Target:   {target_ip}")
    print(f"  Method:   Rapid HTTP requests")
    print(f"  Duration: {duration} seconds")
    print(f"\n  Flooding...")
    
    # Send MANY rapid requests to definitely trigger detection
    print(f"  Sending 300 rapid HTTP requests...")
    host.cmd(f'bash -c \'for i in {{1..300}}; do curl -s -m 0.05 http://{target_ip} > /dev/null 2>&1 & done; wait\' &')
    
    time.sleep(duration + 2)
    
    print(f"\n  ✅ Flood attack completed!")
    print(f"  → Sent 300 parallel HTTP requests")
    print(f"  → Controller should detect >1000 packets in 5 seconds")
    print(f"  → Check controller logs for attack detection")
    print(f"{'='*70}\n")


def simulate_arp_spoof(hostname, fake_ip):
    """Simulate ARP spoofing attack"""
    try:
        frame = sys._getframe(1)
        _net = frame.f_globals.get('net') or frame.f_locals.get('net')
    except:
        _net = None
    
    if _net is None:
        print("Error: Could not find 'net'")
        return
    
    host = _net.get(hostname)
    if not host:
        print(f"Error: Host {hostname} not found!")
        return
    
    iface = f'{hostname}-eth0'
    mac = host.cmd(f'cat /sys/class/net/{iface}/address').strip()
    
    print(f"\n{'='*70}")
    print(f"⚠️  SIMULATING ARP SPOOFING ATTACK")
    print(f"{'='*70}")
    print(f"  Attacker:  {hostname} ({mac})")
    print(f"  Fake IP:   {fake_ip}")
    print(f"  Method:    Gratuitous ARP")
    print(f"\n  Sending fake ARP...")
    
    # Send gratuitous ARP claiming to be fake_ip
    host.cmd(f'arping -c 5 -U -I {iface} -s {fake_ip} {fake_ip} > /dev/null 2>&1 &')
    
    time.sleep(2)
    
    print(f"\n  ✅ ARP spoof sent!")
    print(f"  → Controller should detect IP/MAC mismatch")
    print(f"  → Check controller logs for attack detection")
    print(f"{'='*70}\n")


def simulate_multi_attack(hostname, target_ip):
    """Simulate multiple attack types in sequence"""
    print(f"\n{'='*70}")
    print(f"⚠️  SIMULATING MULTI-STAGE ATTACK")
    print(f"{'='*70}")
    print(f"  This will trigger port scan, then DDoS")
    print(f"  Attacker should be auto-blocked after 3 violations")
    print(f"{'='*70}\n")
    
    print("[Stage 1/3] Port scanning...")
    simulate_port_scan(hostname, target_ip)
    
    time.sleep(3)
    
    print("[Stage 2/3] DDoS attack...")
    simulate_ddos(hostname, target_ip, duration=5)
    
    time.sleep(3)
    
    print("[Stage 3/3] Second port scan...")
    simulate_port_scan(hostname, target_ip)
    
    print(f"\n{'='*70}")
    print("ATTACK SEQUENCE COMPLETE")
    print(f"{'='*70}")
    print(f"  {hostname} should now have 3 violations")
    print(f"  Controller should AUTO-BLOCK the attacker")
    print(f"  Check controller logs for confirmation")
    print(f"{'='*70}\n")


def show_attack_status():
    """Show attack violations for all hosts"""
    import json
    import os
    
    state_file = '/tmp/nac_state.json'
    
    if not os.path.exists(state_file):
        print("No state file found")
        return
    
    with open(state_file, 'r') as f:
        states = json.load(f)
    
    print(f"\n{'='*70}")
    print("ATTACK STATUS REPORT")
    print(f"{'='*70}")
    print(f"{'MAC Address':<17} | {'IP':<15} | {'State':<12} | {'Violations'}")
    print(f"{'-'*17}-+-{'-'*15}-+-{'-'*12}-+-{'-'*10}")
    
    for mac, info in states.items():
        state = info.get('state', 'unknown')
        ip = info.get('ip', 'unknown')
        violations = info.get('violations', 0)
        
        if state == 'approved':
            state_str = '✅ approved'
        elif state == 'blocked':
            state_str = '🚫 blocked'
        else:
            state_str = '🔒 quarantine'
        
        violation_str = f"⚠️  {violations}" if violations > 0 else "0"
        
        print(f"{mac:<17} | {ip:<15} | {state_str:<12} | {violation_str}")
    
    print(f"{'='*70}\n")


# Show help
print("\n" + "="*70)
print("✅ SIMPLE NAC HELPERS LOADED")
print("="*70)
print("\nCommands:")
print("  add_guest('name')        - Add guest to network")
print("  approve_guest('name')    - Approve a guest")
print("  block_guest('name')      - Block a guest")
print("  list_hosts()             - List all hosts")
print("  test_connectivity('name')- Test connectivity")
print("  remove_host('name')      - Remove a host")
print("\nExample workflow:")
print("  mininet> add_guest('laptop1')")
print("  mininet> approve_guest('laptop1')")
print("  mininet> test_connectivity('laptop1')")
print("="*70 + "\n")


def _dashboard_command_listener():
    """Background thread that executes commands from dashboard"""
    import os
    import json
    
    while True:
        try:
            if os.path.exists('/tmp/mininet_commands.json'):
                with open('/tmp/mininet_commands.json', 'r') as f:
                    cmd = json.load(f)
                
                action = cmd.get('action')
                
                if action == 'add_guest':
                    add_guest(cmd.get('hostname', 'guest'), cmd.get('switch', 's7'))
                elif action == 'approve':
                    approve_guest(cmd.get('mac'))
                elif action == 'block':
                    block_guest(cmd.get('mac'))
                elif action == 'simulate_port_scan':
                    simulate_port_scan(cmd.get('hostname'), cmd.get('target'))
                elif action == 'simulate_ddos':
                    simulate_ddos(cmd.get('hostname'), cmd.get('target'), cmd.get('duration', 5))
                elif action == 'simulate_arp_spoof':
                    simulate_arp_spoof(cmd.get('hostname'), cmd.get('fake_ip'))
                
                # Delete command file
                os.remove('/tmp/mininet_commands.json')
                
        except Exception as e:
            pass
        
        time.sleep(0.5)


# Start dashboard listener thread
import threading
dashboard_thread = threading.Thread(target=_dashboard_command_listener, daemon=True)
dashboard_thread.start()
print("📊 Dashboard command listener started")
