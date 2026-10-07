#!/usr/bin/env python
"""
Dynamic Multi-Zone SDN Topology - Network Access Control
No pre-designated attacker - any host can be approved or blocked by admin
"""
from mininet.topo import Topo

class DynamicNACTopo(Topo):
    """Dynamic Network Access Control topology with admin approval system"""
    
    def build(self):
        # Switches (OpenFlow 1.3)
        s1 = self.addSwitch('s1', protocols='OpenFlow13')  # Core
        s2 = self.addSwitch('s2', protocols='OpenFlow13')  # Distributor A
        s3 = self.addSwitch('s3', protocols='OpenFlow13')  # Distributor B
        s4 = self.addSwitch('s4', protocols='OpenFlow13')  # LAN
        s5 = self.addSwitch('s5', protocols='OpenFlow13')  # DMZ
        s6 = self.addSwitch('s6', protocols='OpenFlow13')  # IoT
        s7 = self.addSwitch('s7', protocols='OpenFlow13')  # Guest/Quarantine zone
        
        # ============================================
        # STATIC IP HOSTS (Pre-approved infrastructure)
        # ============================================
        
        # LAN Zone - Employee workstations
        h1 = self.addHost('h1', ip='192.168.1.10/24')
        h2 = self.addHost('h2', ip='192.168.1.11/24')
        
        # DMZ Zone - Public-facing servers
        web = self.addHost('web', ip='192.168.1.20/24')
        ftp = self.addHost('ftp', ip='192.168.1.21/24')
        
        # IoT Zone - Collector (infrastructure)
        collector = self.addHost('collector', ip='192.168.1.35/24')
        
        # ============================================
        # DYNAMIC DHCP HOSTS (Require approval)
        # ============================================
        
        # IoT devices - will need admin approval
        iot1 = self.addHost('iot1', ip='0.0.0.0/24', defaultRoute=None)
        iot2 = self.addHost('iot2', ip='0.0.0.0/24', defaultRoute=None)
        
        # Guest/Unknown devices - quarantined by default
        guest1 = self.addHost('guest1', ip='0.0.0.0/24', defaultRoute=None)
        guest2 = self.addHost('guest2', ip='0.0.0.0/24', defaultRoute=None)
        
        # ============================================
        # Switch Interconnections (Hierarchical)
        # ============================================
        self.addLink(s1, s2, bw=100)  # Core to Distributor A
        self.addLink(s1, s3, bw=100)  # Core to Distributor B
        self.addLink(s2, s4, bw=10)   # Distributor A to LAN
        self.addLink(s2, s5, bw=20)   # Distributor A to DMZ
        self.addLink(s2, s6, bw=5)    # Distributor A to IoT
        self.addLink(s3, s7, bw=10)   # Distributor B to Guest/Quarantine
        
        # ============================================
        # Host Connections
        # ============================================
        
        # LAN hosts
        self.addLink(s4, h1)
        self.addLink(s4, h2)
        
        # DMZ hosts
        self.addLink(s5, web)
        self.addLink(s5, ftp)
        
        # IoT zone
        self.addLink(s6, iot1)
        self.addLink(s6, iot2)
        self.addLink(s6, collector)   # Collector (DHCP server + data sink)
        
        # Guest/Quarantine zone
        self.addLink(s7, guest1)
        self.addLink(s7, guest2)

# Register topology
topos = {'dynamic_nac_topo': DynamicNACTopo}
