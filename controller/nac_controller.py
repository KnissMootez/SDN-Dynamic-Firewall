#!/usr/bin/env python
"""
Dynamic Network Access Control (NAC) Controller - FIXED FOR DYNAMIC HOSTS
Features:
- Proper MAC learning for dynamically added hosts
- Automatic host detection and quarantine
- Admin approval/block system
- DHCP ALWAYS ALLOWED
"""
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4, udp, tcp, icmp
from ryu.lib import hub
from collections import defaultdict
import time
import json
import os

# File for persistent state
STATE_FILE = '/tmp/nac_state.json'

# Zone definitions
ZONE_SWITCHES = {
    'CORE': [1],
    'BACKBONE': [2, 3],
    'LAN': [4],
    'DMZ': [5],
    'IOT': [6],
    'GUEST': [7],
}

# Pre-approved infrastructure (static IPs)
PRE_APPROVED_IPS = [
    '192.168.1.10',  # h1
    '192.168.1.11',  # h2
    '192.168.1.20',  # web
    '192.168.1.21',  # ftp
    '192.168.1.35',  # collector
]

# Attack detection thresholds
PORT_SCAN_THRESHOLD = 20      # More than 20 different ports in 10 seconds
FLOOD_THRESHOLD = 1000        # More than 1000 packets in 5 seconds
ARP_SPOOF_WINDOW = 60         # Detect IP/MAC inconsistencies

class NACController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NACController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapath_to_zone = {dpid: zone for zone, dpids in ZONE_SWITCHES.items() for dpid in dpids}
        self.datapaths = {}
        
        # Host state tracking
        self.host_states = {}
        
        # Track which MACs we've seen (for basic L2 learning)
        self.mac_seen = set()
        
        # Attack detection tracking
        self.port_scan_tracker = defaultdict(lambda: defaultdict(set))
        self.packet_counter = defaultdict(lambda: defaultdict(int))
        self.ip_to_mac = {}
        self.attack_cooldown = {}  # Track last attack time per MAC to prevent spam
        
        # Heuristic risk scoring - collect metrics per MAC
        self.ai_metrics = defaultdict(lambda: {
            'pkt_count': 0,
            'unique_dst_ips': set(),
            'unique_dst_ports': set(),
            'icmp_count': 0,
            'arp_count': 0,
            'syn_count': 0,
            'broadcast_count': 0,
            'last_reset': time.time()
        })
        self.risk_scores = {}  # Current risk score per MAC
        
        # Risk thresholds
        self.AI_RISK_THRESHOLD = 70  # Auto-quarantine if risk > 70%
        
        # Dashboard data
        self.attack_log = []  # Recent attacks for dashboard
        self.flow_tables_cache = {}  # Cache of flow tables for dashboard
        
        # Load previous state if exists
        self.load_state()
        
        # Command file for admin interface
        self.command_file = '/tmp/nac_command.json'
        
        # Start console interface thread
        self.running = True
        self.console_thread = hub.spawn(self._console_interface)
        self.command_monitor = hub.spawn(self._monitor_commands)
        self.ai_loop = hub.spawn(self._ai_risk_scoring_loop)
        self.dashboard_export = hub.spawn(self._export_dashboard_data)
        
        self.logger.info("=" * 70)
        self.logger.info("DYNAMIC NAC CONTROLLER - WITH HEURISTIC RISK SCORING")
        self.logger.info("=" * 70)
        self.logger.info("✅ Proper MAC learning enabled")
        self.logger.info("✅ DHCP always allowed (priority 5000)")
        self.logger.info("✅ Dynamic host support working")
        self.logger.info("✅ Attack detection: Port scan, DDoS, ARP spoof")
        self.logger.info("✅ Heuristic Risk Scoring: Auto-quarantine at >70%% risk")
        self.logger.info("=" * 70)
    
    def load_state(self):
        """Load persistent state from file"""
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE, 'r') as f:
                    self.host_states = json.load(f)
                self.logger.info("Loaded %d host states from file", len(self.host_states))
            except Exception as e:
                self.logger.warning("Could not load state: %s", e)
    
    def save_state(self):
        """Save state to file"""
        try:
            with open(STATE_FILE, 'w') as f:
                json.dump(self.host_states, f, indent=2)
        except Exception as e:
            self.logger.warning("Could not save state: %s", e)
    
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)
    
    def delete_flows(self, datapath, match):
        """Delete flows matching the given match"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('Switch connected: s%d', datapath.id)
                self.datapaths[datapath.id] = datapath
                # Install DHCP flows immediately
                self.install_dhcp_flows(datapath)
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('Switch disconnected: s%d', datapath.id)
                del self.datapaths[datapath.id]

    def install_dhcp_flows(self, datapath):
        """Install DHCP flows with HIGHEST priority on switch"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        self.logger.info("Installing DHCP flows on s%d (priority 5000)", datapath.id)
        
        # DHCP client to server (UDP 68->67) - FLOOD
        match_dhcp_request = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ip_proto=17,  # UDP
            udp_src=68,
            udp_dst=67
        )
        actions_flood = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 5000, match_dhcp_request, actions_flood)
        
        # DHCP server to client (UDP 67->68) - FLOOD
        match_dhcp_response = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ip_proto=17,  # UDP
            udp_src=67,
            udp_dst=68
        )
        self.add_flow(datapath, 5000, match_dhcp_response, actions_flood)
        
        # ARP - FLOOD (needed for DHCP and network discovery)
        match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        self.add_flow(datapath, 5000, match_arp, actions_flood)
        
        self.logger.info("  ✅ DHCP and ARP flows installed")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        # Install table-miss flow entry (send to controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        zone = self.datapath_to_zone.get(dpid, 'UNKNOWN')
        self.logger.info("Configuring s%d - Zone: %s", dpid, zone)
        
        # Install DHCP flows immediately
        self.install_dhcp_flows(datapath)

    def is_infrastructure_host(self, ip):
        """Check if host is pre-approved infrastructure"""
        return ip in PRE_APPROVED_IPS
    
    def get_host_state(self, mac):
        """Get host state, default to unapproved for new hosts"""
        if mac not in self.host_states:
            return 'unapproved'
        return self.host_states[mac].get('state', 'unapproved')
    
    def detect_port_scan(self, mac, dst_port):
        """Detect port scanning behavior"""
        current_time = int(time.time())
        window_start = current_time - 10
        
        # Clean old entries
        to_delete = [ts for ts in self.port_scan_tracker[mac] if ts < window_start]
        for ts in to_delete:
            del self.port_scan_tracker[mac][ts]
        
        # Add current port
        self.port_scan_tracker[mac][current_time].add(dst_port)
        
        # Count unique ports
        unique_ports = set()
        for ports in self.port_scan_tracker[mac].values():
            unique_ports.update(ports)
        
        if len(unique_ports) > PORT_SCAN_THRESHOLD:
            return True, len(unique_ports)
        return False, len(unique_ports)
    
    def detect_flood(self, mac):
        """Detect flooding/DDoS behavior"""
        current_time = int(time.time())
        window_start = current_time - 5
        
        # Clean old entries
        to_delete = [ts for ts in self.packet_counter[mac] if ts < window_start]
        for ts in to_delete:
            del self.packet_counter[mac][ts]
        
        # Increment counter
        self.packet_counter[mac][current_time] += 1
        
        # Count total packets
        total_packets = sum(self.packet_counter[mac].values())
        
        if total_packets > FLOOD_THRESHOLD:
            return True, total_packets
        return False, total_packets
    
    def detect_arp_spoof(self, ip, mac):
        """Detect ARP spoofing"""
        if ip in self.ip_to_mac:
            if self.ip_to_mac[ip] != mac:
                old_mac = self.ip_to_mac[ip]
                return True, old_mac
        else:
            self.ip_to_mac[ip] = mac
        return False, None
    
    def handle_attack(self, mac, attack_type, details=""):
        """Handle detected attack"""
        if mac not in self.host_states:
            return
        
        # Check cooldown - only report same attack type once per 30 seconds
        current_time = time.time()
        cooldown_key = f"{mac}:{attack_type}"
        
        if cooldown_key in self.attack_cooldown:
            time_since_last = current_time - self.attack_cooldown[cooldown_key]
            if time_since_last < 30:
                # Still in cooldown, don't report again
                return
        
        # Update cooldown
        self.attack_cooldown[cooldown_key] = current_time
        
        # Log attack for dashboard
        self.attack_log.append({
            'timestamp': current_time,
            'type': attack_type,
            'mac': mac,
            'ip': self.host_states[mac].get('ip', 'unknown'),
            'details': details,
            'violations': self.host_states[mac].get('violations', 0) + 1
        })
        # Keep only last 100 attacks
        if len(self.attack_log) > 100:
            self.attack_log = self.attack_log[-100:]
        
        # Increment violation counter
        self.host_states[mac]['violations'] = self.host_states[mac].get('violations', 0) + 1
        violations = self.host_states[mac]['violations']
        
        self.logger.warning("=" * 70)
        self.logger.warning("⚠️  ATTACK DETECTED!")
        self.logger.warning("=" * 70)
        self.logger.warning("  Type:       %s", attack_type)
        self.logger.warning("  Source MAC: %s", mac)
        self.logger.warning("  Source IP:  %s", self.host_states[mac].get('ip', 'unknown'))
        self.logger.warning("  Switch:     s%d", self.host_states[mac].get('switch', 0))
        self.logger.warning("  Details:    %s", details)
        self.logger.warning("  Violations: %d", violations)
        
        # Auto-block after 3 violations
        if violations >= 3:
            self.logger.warning("  Action:     AUTO-BLOCKING (>= 3 violations)")
            self.logger.warning("=" * 70)
            self.block_host(mac)
        else:
            self.logger.warning("  Action:     WARNING ISSUED (cooldown: 30s)")
            self.logger.warning("=" * 70)
        
        self.save_state()
    
    def register_new_host(self, mac, ip, switch, port):
        """Register a new host in unapproved state (or auto-approve if IoT)"""
        if mac in self.host_states:
            # Update IP if changed
            if self.host_states[mac].get('ip') != ip:
                self.host_states[mac]['ip'] = ip
            return
        
        # Check if this is an IoT device
        auto_approve = False
        zone = self.datapath_to_zone.get(switch, 'UNKNOWN')
        
        if zone == 'IOT' and ip.startswith('192.168.1.'):
            last_octet = int(ip.split('.')[-1])
            if 100 <= last_octet <= 149:
                auto_approve = True
        
        # Initial state
        initial_state = 'approved' if auto_approve else 'unapproved'
        
        self.host_states[mac] = {
            'state': initial_state,
            'ip': ip,
            'switch': switch,
            'port': port,
            'first_seen': time.time(),
            'violations': 0
        }
        
        if auto_approve:
            self.logger.warning("=" * 70)
            self.logger.warning("🤖 IOT DEVICE AUTO-APPROVED")
            self.logger.warning("  MAC: %s | IP: %s | Switch: s%d", mac, ip, switch)
            self.logger.warning("=" * 70)
        else:
            self.logger.warning("=" * 70)
            self.logger.warning("🔔 NEW HOST DETECTED - QUARANTINED")
            self.logger.warning("  MAC: %s | IP: %s | Switch: s%d", mac, ip, switch)
            self.logger.warning("  Action: python3 nac_admin.py approve %s", mac)
            self.logger.warning("=" * 70)
            
            # Install quarantine flows
            self.install_quarantine_flows(mac, switch)
        
        self.save_state()
    
    def install_quarantine_flows(self, mac, switch_id):
        """Install flows for quarantined host (limited access)"""
        if switch_id not in self.datapaths:
            return
        
        datapath = self.datapaths[switch_id]
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        self.logger.info("Installing QUARANTINE for MAC %s on s%d", mac, switch_id)
        
        # Allow ICMP to gateway (for testing)
        match_ping = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            eth_src=mac,
            ip_proto=1,  # ICMP
            ipv4_dst='192.168.1.35'
        )
        actions_flood = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 500, match_ping, actions_flood)
        
        # Block everything else from this MAC
        match_block = parser.OFPMatch(eth_src=mac)
        self.add_flow(datapath, 100, match_block, [])  # Drop
        
        self.logger.info("  → Quarantine active (DHCP still works at priority 5000)")
    
    def install_approved_flows(self, mac, switch_id):
        """Install flows for approved host (normal access)"""
        if switch_id not in self.datapaths:
            return
        
        datapath = self.datapaths[switch_id]
        parser = datapath.ofproto_parser
        
        self.logger.info("Installing APPROVED flows for MAC %s on s%d", mac, switch_id)
        
        # Remove quarantine flows
        match_delete = parser.OFPMatch(eth_src=mac)
        self.delete_flows(datapath, match_delete)
        
        self.logger.info("  → Full network access granted")
    
    def install_blocked_flows(self, mac):
        """Install flows to block host on ALL switches"""
        self.logger.info("Installing BLOCKED flows for MAC %s on all switches", mac)
        
        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser
            
            # Block all traffic from this MAC (even higher than DHCP!)
            match_block = parser.OFPMatch(eth_src=mac)
            self.add_flow(datapath, 6000, match_block, [])
            
            self.logger.info("  → s%d: Blocked", dpid)
    
    def approve_host(self, mac):
        """Approve a host for network access"""
        if mac not in self.host_states:
            self.logger.error("Unknown MAC: %s", mac)
            return False
        
        if self.host_states[mac]['state'] == 'approved':
            self.logger.info("Host %s already approved", mac)
            return True
        
        self.logger.warning("=" * 70)
        self.logger.warning("✅ APPROVING HOST: %s", mac)
        self.logger.warning("=" * 70)
        
        self.host_states[mac]['state'] = 'approved'
        self.save_state()
        
        switch = self.host_states[mac].get('switch')
        self.install_approved_flows(mac, switch)
        
        return True
    
    def block_host(self, mac):
        """Block a host from network access"""
        if mac not in self.host_states:
            self.logger.error("Unknown MAC: %s", mac)
            return False
        
        self.logger.warning("=" * 70)
        self.logger.warning("🚫 BLOCKING HOST: %s", mac)
        self.logger.warning("=" * 70)
        
        self.host_states[mac]['state'] = 'blocked'
        self.save_state()
        
        self.install_blocked_flows(mac)
        
        return True
    
    def list_hosts(self):
        """List all known hosts"""
        self.logger.info("=" * 70)
        self.logger.info("HOST STATUS REPORT")
        self.logger.info("=" * 70)
        
        if not self.host_states:
            self.logger.info("No hosts registered yet")
            return
        
        for mac, info in self.host_states.items():
            state = info.get('state', 'unknown')
            ip = info.get('ip', 'unknown')
            switch = info.get('switch', '?')
            violations = info.get('violations', 0)
            icon = {'approved': '✅', 'unapproved': '🔒', 'blocked': '🚫'}.get(state, '❓')
            
            violation_str = f" (⚠️  {violations} violations)" if violations > 0 else ""
            self.logger.info("%s %s → %s (s%s)%s", icon, mac, ip, switch, violation_str)
        
        self.logger.info("=" * 70)
    
    def _console_interface(self):
        """Admin console interface"""
        self.logger.info("\nAdmin interface ready: python3 nac_admin.py\n")
        while self.running:
            hub.sleep(1)
    
    def calculate_risk_score(self, mac):
        """Calculate risk score (0-100) for a MAC address using heuristics"""
        metrics = self.ai_metrics[mac]
        
        # Get time window
        time_window = time.time() - metrics['last_reset']
        if time_window == 0:
            time_window = 1
        
        # Calculate rates
        pkt_rate = metrics['pkt_count'] / time_window
        unique_ips = len(metrics['unique_dst_ips'])
        unique_ports = len(metrics['unique_dst_ports'])
        broadcast_ratio = metrics['broadcast_count'] / max(metrics['pkt_count'], 1)
        
        # Heuristic scoring (0-100)
        risk = 0
        
        # High packet rate (>100 pkt/s suspicious)
        if pkt_rate > 100:
            risk += min(30, (pkt_rate / 100) * 15)
        
        # Many unique IPs (>10 IPs suspicious - could be scanning)
        if unique_ips > 10:
            risk += min(25, (unique_ips / 10) * 12)
        
        # Many unique ports (>15 ports suspicious - port scanning)
        if unique_ports > 15:
            risk += min(30, (unique_ports / 15) * 15)
        
        # High ICMP (>50 ICMP suspicious - could be flood/scan)
        if metrics['icmp_count'] > 50:
            risk += min(10, (metrics['icmp_count'] / 50) * 5)
        
        # High SYN (>20 SYN suspicious - port scan)
        if metrics['syn_count'] > 20:
            risk += min(10, (metrics['syn_count'] / 20) * 5)
        
        # High broadcast ratio (>30% suspicious)
        if broadcast_ratio > 0.3:
            risk += min(5, (broadcast_ratio / 0.3) * 2.5)
        
        return min(100, risk)
    
    def _ai_risk_scoring_loop(self):
        """Risk scoring loop - runs every 10 seconds to calculate heuristic risk scores"""
        self.logger.info("📈 Heuristic Risk Scoring started (10s interval)")
        
        while self.running:
            hub.sleep(10)
            
            current_time = time.time()
            
            # Calculate risk for each tracked MAC
            for mac in list(self.ai_metrics.keys()):
                metrics = self.ai_metrics[mac]
                
                # Skip if no activity
                if metrics['pkt_count'] == 0:
                    continue
                
                # Calculate risk score
                risk_score = self.calculate_risk_score(mac)
                self.risk_scores[mac] = risk_score
                
                # ALWAYS log risk for approved hosts (for demo/debugging)
                if mac in self.host_states:
                    state = self.host_states[mac].get('state')
                    ip = self.host_states[mac].get('ip', 'unknown')
                    
                    if state == 'approved':
                        self.logger.info("📈 Risk: %s (%s) = %.1f%% [pkt/s:%.1f, IPs:%d, ports:%d]",
                                       mac, ip, risk_score,
                                       metrics['pkt_count'] / max(current_time - metrics['last_reset'], 1),
                                       len(metrics['unique_dst_ips']),
                                       len(metrics['unique_dst_ports']))
                    
                    # Auto-quarantine if risk too high and host is approved
                    if risk_score > self.AI_RISK_THRESHOLD and state == 'approved':
                        self.logger.warning("=" * 70)
                        self.logger.warning("📈 RISK AUTO-QUARANTINE")
                        self.logger.warning("=" * 70)
                        self.logger.warning("  MAC:        %s", mac)
                        self.logger.warning("  IP:         %s", ip)
                        self.logger.warning("  Risk Score: %.1f%% (threshold: %d%%)", risk_score, self.AI_RISK_THRESHOLD)
                        self.logger.warning("  Reason:     Suspicious behavior detected")
                        self.logger.warning("=" * 70)
                        
                        # Change state to unapproved and install quarantine
                        self.host_states[mac]['state'] = 'unapproved'
                        self.host_states[mac]['violations'] = self.host_states[mac].get('violations', 0) + 1
                        self.save_state()
                        
                        switch = self.host_states[mac].get('switch')
                        self.install_quarantine_flows(mac, switch)
                
                # Reset metrics for next window
                self.ai_metrics[mac] = {
                    'pkt_count': 0,
                    'unique_dst_ips': set(),
                    'unique_dst_ports': set(),
                    'icmp_count': 0,
                    'arp_count': 0,
                    'syn_count': 0,
                    'broadcast_count': 0,
                    'last_reset': current_time
                }
    
    
    def _export_dashboard_data(self):
        """Export data for dashboard every 2 seconds"""
        self.logger.info("📊 Dashboard data export started (2s interval)")
        
        while self.running:
            try:
                # Request flow stats from all switches
                self.request_flow_stats()
                
                # Export topology
                topology = {
                    'switches': [],
                    'hosts': [],
                    'links': []
                }
                
                # Add switches
                for dpid in self.datapaths.keys():
                    zone = self.datapath_to_zone.get(dpid, 'UNKNOWN')
                    topology['switches'].append({
                        'id': f's{dpid}',
                        'zone': zone
                    })
                
                # Add infrastructure hosts (static)
                infrastructure = [
                    {'hostname': 'h1', 'ip': '192.168.1.10', 'switch': 4},
                    {'hostname': 'h2', 'ip': '192.168.1.11', 'switch': 4},
                    {'hostname': 'web', 'ip': '192.168.1.20', 'switch': 5},
                    {'hostname': 'ftp', 'ip': '192.168.1.21', 'switch': 5},
                    {'hostname': 'collector', 'ip': '192.168.1.35', 'switch': 6}
                ]
                
                # First, check if these infrastructure IPs exist in host_states (they might be discovered)
                infra_ips = {infra['ip']: infra for infra in infrastructure}
                discovered_infra = {}
                
                for mac, info in self.host_states.items():
                    if info.get('ip') in infra_ips:
                        # This infrastructure host was discovered
                        discovered_infra[info['ip']] = {
                            'mac': mac,
                            'hostname': infra_ips[info['ip']]['hostname'],
                            'violations': info.get('violations', 0)
                        }
                
                for infra in infrastructure:
                    if infra['ip'] in discovered_infra:
                        # Use discovered data
                        disc = discovered_infra[infra['ip']]
                        topology['hosts'].append({
                            'id': disc['mac'],
                            'label': f"{infra['hostname']}\n{infra['ip']}",
                            'state': 'approved',
                            'switch': f"s{infra['switch']}",
                            'risk': self.risk_scores.get(disc['mac'], 0),
                            'violations': disc['violations']
                        })
                        # Add link
                        topology['links'].append({
                            'from': disc['mac'],
                            'to': f"s{infra['switch']}"
                        })
                    else:
                        # Not discovered yet, use placeholder
                        topology['hosts'].append({
                            'id': f"infra:{infra['hostname']}",
                            'label': f"{infra['hostname']}\n{infra['ip']}",
                            'state': 'approved',
                            'switch': f"s{infra['switch']}",
                            'risk': 0,
                            'violations': 0
                        })
                        # Add link
                        topology['links'].append({
                            'from': f"infra:{infra['hostname']}",
                            'to': f"s{infra['switch']}"
                        })
                
                # Add dynamic hosts (skip ones we already added as infrastructure)
                infra_ips_set = set(infra_ips.keys())
                for mac, info in self.host_states.items():
                    if info.get('ip') not in infra_ips_set:
                        # Get hostname if available (check for iot1, iot2, guest1, guest2 pattern)
                        ip = info.get('ip', 'unknown')
                        hostname = 'unknown'
                        
                        # Try to infer hostname from IP
                        if ip.startswith('192.168.1.'):
                            last_octet = int(ip.split('.')[-1])
                            # IoT range 100-149
                            if 100 <= last_octet <= 149:
                                hostname = f'iot{last_octet - 99}'  # iot1, iot2, etc
                            # Guest range 150-200
                            elif 150 <= last_octet <= 200:
                                hostname = f'guest{last_octet - 149}'  # guest1, guest2, etc
                        
                        topology['hosts'].append({
                            'id': mac,
                            'label': f"{hostname}\n{ip}" if hostname != 'unknown' else ip,
                            'state': info.get('state', 'unknown'),
                            'switch': f"s{info.get('switch', 0)}",
                            'risk': self.risk_scores.get(mac, 0),
                            'violations': info.get('violations', 0)
                        })
                
                # Add links (host to switch) for dynamic hosts
                for mac, info in self.host_states.items():
                    if info.get('ip') not in infra_ips_set:
                        topology['links'].append({
                            'from': mac,
                            'to': f"s{info.get('switch', 0)}"
                        })
                
                # Add switch-to-switch links (based on ZONE_SWITCHES)
                switch_links = [
                    ('s1', 's2'), ('s1', 's3'),
                    ('s2', 's4'), ('s2', 's5'), ('s2', 's6'),
                    ('s3', 's7')
                ]
                for link in switch_links:
                    topology['links'].append({'from': link[0], 'to': link[1]})
                
                with open('/tmp/topology.json', 'w') as f:
                    json.dump(topology, f, indent=2)
                
                with open('/tmp/topology.json', 'w') as f:
                    json.dump(topology, f, indent=2)
                
                # Export risk metrics
                ai_data = {}
                for mac in self.risk_scores.keys():
                    if mac in self.host_states:
                        ai_data[mac] = {
                            'risk_score': self.risk_scores[mac],
                            'ip': self.host_states[mac].get('ip', 'unknown'),
                            'state': self.host_states[mac].get('state', 'unknown')
                        }
                
                with open('/tmp/ai_metrics.json', 'w') as f:
                    json.dump(ai_data, f, indent=2)
                
                # Export attack log
                with open('/tmp/attack_log.json', 'w') as f:
                    json.dump(self.attack_log[-50:], f, indent=2)  # Last 50 attacks
                
                # Export OpenFlow flow tables
                flows_data = {}
                for dpid, datapath in self.datapaths.items():
                    parser = datapath.ofproto_parser
                    ofproto = datapath.ofproto
                    
                    # Request flow stats
                    req = parser.OFPFlowStatsRequest(datapath)
                    # We'll handle this via a stats reply handler
                    
                with open('/tmp/flow_tables.json', 'w') as f:
                    json.dump(getattr(self, 'flow_tables_cache', {}), f, indent=2)
                
            except Exception as e:
                self.logger.debug("Dashboard export error: %s", e)
            
            hub.sleep(2)
    
    def _monitor_commands(self):
        """Monitor command file for admin commands"""
        last_mtime = 0
        
        while self.running:
            try:
                if os.path.exists(self.command_file):
                    mtime = os.path.getmtime(self.command_file)
                    if mtime > last_mtime:
                        last_mtime = mtime
                        
                        with open(self.command_file, 'r') as f:
                            cmd = json.load(f)
                        
                        command = cmd.get('command')
                        mac = cmd.get('mac')
                        
                        if command == 'approve' and mac:
                            self.approve_host(mac)
                        elif command == 'block' and mac:
                            self.block_host(mac)
                        elif command == 'list':
                            self.list_hosts()
                        
                        os.remove(self.command_file)
            except Exception as e:
                self.logger.debug("Command monitor error: %s", e)
            
            hub.sleep(0.5)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        # CRITICAL: Learn MAC address to port mapping IMMEDIATELY
        # This is what was missing - we need to learn ALL MACs, not just registered hosts
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        
        # Mark that we've seen this MAC
        if src not in self.mac_seen:
            self.mac_seen.add(src)
            self.logger.info("Learned new MAC: %s on s%d port %d", src, dpid, in_port)
        
        # Risk: Collect metrics for risk scoring
        if src in self.host_states or src not in PRE_APPROVED_IPS:
            # Track packet
            self.ai_metrics[src]['pkt_count'] += 1
            
            # Track broadcasts
            if dst == 'ff:ff:ff:ff:ff:ff':
                self.ai_metrics[src]['broadcast_count'] += 1

        # Check if this is a new host with valid IP (for registration)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)
        
        # Attack detection - ARP spoofing
        if arp_pkt and arp_pkt.src_ip != '0.0.0.0':
            # Risk: Track ARP packets
            if src in self.ai_metrics:
                self.ai_metrics[src]['arp_count'] += 1
            
            is_spoof, old_mac = self.detect_arp_spoof(arp_pkt.src_ip, src)
            if is_spoof and src in self.host_states:
                self.handle_attack(src, "ARP Spoofing", 
                                 f"IP {arp_pkt.src_ip} claimed by {src} (was {old_mac})")
        
        # Attack detection and registration for IP packets
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            
            # Risk: Track destination IPs
            if src in self.ai_metrics and dst_ip != '0.0.0.0':
                self.ai_metrics[src]['unique_dst_ips'].add(dst_ip)
            
            # Risk: Track ICMP
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt and src in self.ai_metrics:
                self.ai_metrics[src]['icmp_count'] += 1
            
            if src_ip != '0.0.0.0':
                # Check for attacks from ALL hosts (including infrastructure)
                # Register infrastructure hosts if not already tracked
                if src not in self.host_states and self.is_infrastructure_host(src_ip):
                    # Auto-register and approve infrastructure hosts
                    self.host_states[src] = {
                        'ip': src_ip,
                        'switch': dpid,
                        'port': in_port,
                        'state': 'approved',  # Infrastructure auto-approved
                        'violations': 0,
                        'first_seen': time.time()
                    }
                    self.ai_metrics[src] = {
                        'pkt_count': 0,
                        'unique_dst_ips': set(),
                        'unique_dst_ports': set(),
                        'icmp_count': 0,
                        'arp_count': 0,
                        'syn_count': 0,
                        'broadcast_count': 0,
                        'last_reset': time.time()
                    }
                    self.logger.info("📌 Infrastructure host auto-registered: %s (%s)", src, src_ip)
                
                # Check for attacks from ALL registered hosts (infrastructure + dynamic)
                if src in self.host_states:
                    state = self.host_states[src].get('state')
                    
                    # Only detect attacks from approved hosts (not quarantined)
                    # CRITICAL: Only count packets INITIATED by this host (not responses)
                    # Check if this is eth_src (sender) not eth_dst (receiver)
                    if state == 'approved' and src == eth.src:
                        # Additional check: Don't count response packets
                        # For TCP, only count SYN packets (new connections)
                        # For flooding, only count if dst_ip is not from our network responding
                        tcp_pkt = pkt.get_protocol(tcp.tcp)
                        
                        # Detect port scanning (only SYN packets)
                        if tcp_pkt:
                            dst_port = tcp_pkt.dst_port
                            src_port = tcp_pkt.src_port
                            
                            # Check if this is a server response (not client request)
                            is_server_response = src_port < 1024
                            
                            # Risk: Only track destination ports for CLIENT requests (not server responses)
                            if src in self.ai_metrics and not is_server_response:
                                self.ai_metrics[src]['unique_dst_ports'].add(dst_port)
                            
                            # Only count SYN packets for port scanning (not responses)
                            if tcp_pkt.bits & 0x02:  # SYN flag
                                # Exclude SYN-ACK (server responses)
                                # SYN-ACK has both SYN (0x02) and ACK (0x10) flags set
                                is_syn_ack = (tcp_pkt.bits & 0x12) == 0x12
                                
                                # Also exclude if source port is a well-known server port
                                is_server_response = tcp_pkt.src_port < 1024
                                
                                if not is_syn_ack and not is_server_response:
                                    # Risk: Track SYN packets (client initiating connections)
                                    if src in self.ai_metrics:
                                        self.ai_metrics[src]['syn_count'] += 1
                                    
                                    is_scan, port_count = self.detect_port_scan(src, dst_port)
                                    if is_scan:
                                        self.handle_attack(src, "Port Scanning", 
                                                         f"Scanned {port_count} ports in 10 seconds")
                        
                        # Detect flooding (only count outgoing NEW connections)
                        # Don't count if this is a server responding to requests
                        # Check: Is destination port < 1024? (Server port = response)
                        is_likely_response = False
                        if tcp_pkt and tcp_pkt.src_port < 1024:
                            # Source port < 1024 = server responding
                            is_likely_response = True
                        
                        if not is_likely_response:
                            is_flood, packet_count = self.detect_flood(src)
                            if is_flood:
                                self.handle_attack(src, "DDoS/Flooding", 
                                                 f"{packet_count} packets in 5 seconds from {src_ip}")
                        
                        # Risk: Also track UDP ports
                        udp_pkt = pkt.get_protocol(udp.udp)
                        if udp_pkt and src in self.ai_metrics:
                            self.ai_metrics[src]['unique_dst_ports'].add(udp_pkt.dst_port)
                
                # Register NEW non-infrastructure hosts (infrastructure already registered above)
                elif src not in self.host_states and not self.is_infrastructure_host(src_ip):
                    self.register_new_host(src, src_ip, dpid, in_port)

        # Determine output port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow for known destinations (basic L2 learning)
        if out_port != ofproto.OFPP_FLOOD:
            # For approved hosts, send a COPY to controller for attack detection
            # while still forwarding normally
            if src in self.host_states and self.host_states[src].get('state') == 'approved':
                # Install flow with BOTH forward AND controller actions
                actions_with_monitor = [
                    parser.OFPActionOutput(out_port),
                    parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 128)  # Send first 128 bytes to controller
                ]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(datapath, 10, match, actions_with_monitor, idle_timeout=30, hard_timeout=60)
            else:
                # For non-approved hosts, just normal forwarding
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(datapath, 10, match, actions, idle_timeout=30, hard_timeout=60)

        # Send packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Handle flow stats replies"""
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        
        flows = []
        for stat in body:
            match_dict = {}
            for field, value in stat.match.items():
                match_dict[field] = str(value)
            
            flow = {
                'priority': stat.priority,
                'match': match_dict,
                'actions': [],
                'idle_timeout': stat.idle_timeout,
                'hard_timeout': stat.hard_timeout,
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count
            }
            
            # Parse actions
            for inst in stat.instructions:
                if hasattr(inst, 'actions'):
                    for act in inst.actions:
                        action_str = str(act)
                        flow['actions'].append(action_str)
            
            flows.append(flow)
        
        # Sort by priority (highest first)
        flows.sort(key=lambda x: x['priority'], reverse=True)
        
        self.flow_tables_cache[f's{dpid}'] = flows
    
    def request_flow_stats(self):
        """Request flow stats from all switches"""
        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser
            req = parser.OFPFlowStatsRequest(datapath)
            datapath.send_msg(req)
