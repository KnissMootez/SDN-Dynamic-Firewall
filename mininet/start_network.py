#!/usr/bin/env python
"""
Launch script for Dynamic Network Access Control (NAC) System - WORKING DHCP
"""
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
from sdn_multi_zone_topo import DynamicNACTopo
import time
import os

def start_nac_network():
    setLogLevel('info')
    import os
    os.system('rm -f /tmp/nac_state.json /tmp/topology.json /tmp/ai_metrics.json /tmp/attack_log.json')
    
    print("\n" + "=" * 70)
    print("DYNAMIC NETWORK ACCESS CONTROL (NAC) SYSTEM - DHCP FIX")
    print("=" * 70)
    
    # Create network
    print("\n[1/5] Creating network topology...")
    topo = DynamicNACTopo()
    net = Mininet(topo=topo, controller=RemoteController, waitConnected=True)
    
    # Start network
    print("[2/5] Starting network...")
    net.start()
    
    print("[3/5] Setting up DHCP server...")
    
    # Get hosts
    collector = net.get('collector')
    iot1 = net.get('iot1')
    iot2 = net.get('iot2')
    guest1 = net.get('guest1')
    guest2 = net.get('guest2')
    
    # Step 1: Set collector IP
    print("    Setting collector IP to 192.168.1.35...")
    collector.cmd('ifconfig collector-eth0 192.168.1.35 netmask 255.255.255.0 up')
    time.sleep(1)
    
    # Step 2: Kill any existing dnsmasq
    os.system('sudo killall dnsmasq 2>/dev/null')
    time.sleep(1)
    
    # Step 3: Get MAC addresses
    iot1_mac = iot1.cmd('cat /sys/class/net/iot1-eth0/address').strip()
    iot2_mac = iot2.cmd('cat /sys/class/net/iot2-eth0/address').strip()
    
    print(f"    IoT1 MAC: {iot1_mac}")
    print(f"    IoT2 MAC: {iot2_mac}")
    
    # Step 4: Create SIMPLE DHCP config
    dhcp_config = f"""
# === IoT DEVICES (Auto-Approve Range) ===
# Tag known IoT devices
dhcp-host={iot1_mac},set:iot,192.168.1.100
dhcp-host={iot2_mac},set:iot,192.168.1.101

# IoT range - ONLY for devices tagged as 'iot'
dhcp-range=tag:iot,192.168.1.100,192.168.1.149,12h

# === GUEST DEVICES (Quarantine Range) ===
# Guest range - for devices NOT tagged as 'iot'
dhcp-range=tag:!iot,192.168.1.150,192.168.1.200,12h

# Gateway
dhcp-option=3,192.168.1.35
# DNS
dhcp-option=6,8.8.8.8

# Logging
log-dhcp
log-facility=/tmp/dnsmasq.log
"""
    
    # Write config
    with open('/tmp/dnsmasq_nac.conf', 'w') as f:
        f.write(dhcp_config)
    
    print("    Starting dnsmasq...")
    
    # Start dnsmasq with NO DAEMON
    collector.cmd('rm -f /tmp/dnsmasq.log')
    collector.cmd('dnsmasq '
                  '--no-daemon '
                  '--interface=collector-eth0 '
                  '--bind-interfaces '
                  '--dhcp-authoritative '
                  '--conf-file=/tmp/dnsmasq_nac.conf '
                  '--dhcp-leasefile=/tmp/dnsmasq.leases '
                  '> /tmp/dnsmasq_output.log 2>&1 &')
    
    time.sleep(3)
    
    # Verify dnsmasq is running
    result = collector.cmd('ps aux | grep dnsmasq | grep -v grep')
    if 'dnsmasq' in result:
        print("    ✅ DHCP server is running")
    else:
        print("    ❌ DHCP server failed!")
        print(collector.cmd('cat /tmp/dnsmasq_output.log'))
    
    # Step 5: Install MANUAL DHCP FLOWS (bypass controller)
    print("[4/5] Installing MANUAL DHCP flows on all switches...")
    
    # Get all switches
    switches = net.switches
    for switch in switches:
        switch_name = switch.name
        print(f"    Installing DHCP flows on {switch_name}...")
        
        # Clear existing flows
        switch.cmd(f'ovs-ofctl del-flows {switch_name}')
        
        # Install DHCP flows (BROADCAST to all ports)
        switch.cmd(f'ovs-ofctl add-flow {switch_name} "priority=1000,udp,tp_src=68,tp_dst=67,actions=flood"')
        switch.cmd(f'ovs-ofctl add-flow {switch_name} "priority=1000,udp,tp_src=67,tp_dst=68,actions=flood"')
        switch.cmd(f'ovs-ofctl add-flow {switch_name} "priority=1000,arp,actions=flood"')
        
        # Send everything else to controller
        switch.cmd(f'ovs-ofctl add-flow {switch_name} "priority=100,actions=CONTROLLER"')
    
    print("    ✅ Manual DHCP flows installed")
    time.sleep(2)
    
    print("[5/5] Getting DHCP addresses...")
    
    # Reset all DHCP clients
    dhcp_hosts = {
        'iot1': iot1,
        'iot2': iot2,
        'guest1': guest1,
        'guest2': guest2
    }
    
    for name, host in dhcp_hosts.items():
    	
        ip=0
        while (ip==0):
            time.sleep(5)
            iface = f'{name}-eth0'
            
            print(f"\n    Getting IP for {name}...")
            
            # Reset interface
            host.cmd(f'ifconfig {iface} 0.0.0.0 down')
            host.cmd(f'ifconfig {iface} up')
            host.cmd(f'killall -9 dhclient 2>/dev/null')
            host.cmd(f'rm -f /var/lib/dhcp/dhclient.leases')
            host.cmd(f'rm -f /var/lib/dhcp/dhclient.{iface}.leases')
            host.cmd(f'rm -f /var/lib/dhclient/*')
            # Request DHCP with timeout
            host.cmd(f'timeout 10 dhclient -v {iface} > /tmp/dhclient_{name}.log 2>&1')
        
            # Check result
            ip = host.cmd(f'ip -4 addr show {iface} | grep inet | awk \'{{print $2}}\'').strip()

            if ip:
                print(f"      ✅ {name} got IP: {ip}")
                
                # Check which range
                ip_num = int(ip.split('/')[0].split('.')[-1])
                if 100 <= ip_num <= 149:
                    print(f"      📍 IoT range (auto-approved by controller)")
                elif 150 <= ip_num <= 200:
                    print(f"      📍 Guest range (quarantined by controller)")
            else:
                ip=0
                #print(f"      ❌ {name} failed to get IP")
                #print(f"      Log: {host.cmd('tail -5 /tmp/dhclient_' + name + '.log')}")
    
    # Start services
    print("\nStarting services...")
    
    web = net.get('web')
    web.cmd('mkdir -p /tmp/webroot')
    web.cmd('echo "<h1>DMZ Web Server</h1>" > /tmp/webroot/index.html')
    web.cmd('cd /tmp/webroot && python3 -m http.server 80 > /tmp/web.log 2>&1 &')
    print("    ✅ Web server running (192.168.1.20:80)")
    
    ftp = net.get('ftp')
    ftp.cmd('mkdir -p /tmp/ftproot')
    ftp.cmd('while true; do echo "220 FTP Ready" | nc -l -p 21; done > /tmp/ftp.log 2>&1 &')
    print("    ✅ FTP server running (192.168.1.21:21)")
    
    # Final status
    print("\n" + "=" * 70)
    print("NAC SYSTEM STATUS")
    print("=" * 70)
    
    print("\nStatic Infrastructure:")
    print("  h1:       192.168.1.10")
    print("  h2:       192.168.1.11")
    print("  web:      192.168.1.20")
    print("  ftp:      192.168.1.21")
    print("  collector:192.168.1.35")
    
    print("\nDynamic Hosts (Controller will handle):")
    for name in ['iot1', 'iot2', 'guest1', 'guest2']:
        host = net.get(name)
        iface = f'{name}-eth0'
        ip = host.cmd(f'ip -4 addr show {iface} | grep inet | awk \'{{print $2}}\'').strip()
        if ip:
            ip_clean = ip.split('/')[0]
            last_octet = int(ip_clean.split('.')[-1])
            if 100 <= last_octet <= 149:
                status = "🤖 IoT (auto-approve)"
            elif 150 <= last_octet <= 200:
                status = "🔒 Guest (quarantine)"
            else:
                status = "❓ Unknown"
            print(f"  {name}: {ip_clean:15} {status}")
        else:
            print(f"  {name}: No IP")
    
    print("\n" + "=" * 70)
    print("TROUBLESHOOTING")
    print("=" * 70)
    print("If DHCP still fails:")
    print("1. Check DHCP server: collector cat /tmp/dnsmasq_output.log")
    print("2. Check DHCP client: iot1 cat /tmp/dhclient_iot1.log")
    print("3. Test connectivity: iot1 ping 192.168.1.35")
    print("4. Check switch flows: s1 ovs-ofctl dump-flows s1 | grep 67")
    print("5. Manual DHCP: iot1 dhclient -v iot1-eth0")
    print("=" * 70)
    
    # Start Mininet CLI
    CLI(net)
    
    # Cleanup
    print("\nCleaning up...")
    net.stop()
    os.system('sudo killall dnsmasq 2>/dev/null')
    import builtins

# After net.start() and before CLI(net), add this:
    def make_net_global(net_instance):
        """Make net accessible globally for dashboard listener"""
        builtins.__dict__['GLOBAL_NET'] = net_instance
        print("✅ Network exposed globally for dashboard")

if __name__ == '__main__':
    start_nac_network()
