import random
import socket
import time
from datetime import timedelta
from django.utils import timezone
from .models import Device, SecurityAlert, TrafficSnapshot, ActivityLog, DetectionRule

DEFAULT_RULES = [
    {
        'code': 'RULE-01',
        'name': 'Rapid Port Scan Detection',
        'description': 'Detects single host contacting multiple distinct destination ports (>= 8 ports) within 15 seconds.',
        'rule_type': 'PORT_SCAN',
        'threshold_value': 8.0,
        'time_window_seconds': 15,
        'severity': 'CRITICAL',
    },
    {
        'code': 'RULE-02',
        'name': 'Excessive Connection Rate',
        'description': 'Detects abnormal connection frequency (> 35 connections per 10s) indicating SYN flood or scanning.',
        'rule_type': 'CONNECTION_BURST',
        'threshold_value': 35.0,
        'time_window_seconds': 10,
        'severity': 'HIGH',
    },
    {
        'code': 'RULE-03',
        'name': 'Abnormal Traffic Bandwidth Spike',
        'description': 'Detects abnormal packet volume (> 100 packets/sec) exceeding typical local network baseline.',
        'rule_type': 'ABNORMAL_TRAFFIC',
        'threshold_value': 100.0,
        'time_window_seconds': 5,
        'severity': 'HIGH',
    },
    {
        'code': 'RULE-04',
        'name': 'Suspicious Management Port Probing',
        'description': 'Flags unauthorized attempts to reach legacy or sensitive administrative ports (Telnet 23, SMB 445, MS-RPC 135).',
        'rule_type': 'SUSPICIOUS_PORT',
        'threshold_value': 1.0,
        'time_window_seconds': 30,
        'severity': 'MEDIUM',
    },
]

def initialize_rules():
    """Ensure baseline detection rules are populated in relational database."""
    for r in DEFAULT_RULES:
        DetectionRule.objects.get_or_create(
            code=r['code'],
            defaults={
                'name': r['name'],
                'description': r['description'],
                'rule_type': r['rule_type'],
                'threshold_value': r['threshold_value'],
                'time_window_seconds': r['time_window_seconds'],
                'severity': r['severity'],
                'is_enabled': True,
                'times_triggered': 0,
            }
        )

def get_system_network_info():
    """Obtain local host network telemetry using standard socket library."""
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "127.0.0.1"

    # Derive local subnet/gateway approximation
    ip_parts = local_ip.split('.')
    if len(ip_parts) == 4 and ip_parts[0] != '127':
        subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        gateway = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1"
    else:
        subnet = "192.168.1.0/24"
        gateway = "192.168.1.1"

    return {
        'hostname': hostname,
        'local_ip': local_ip,
        'subnet': subnet,
        'gateway': gateway,
        'interface': 'Wi-Fi / Ethernet Adapter (Monitored)',
    }

def seed_sample_data_if_empty():
    """Seed initial network devices, snapshots, and logs if DB is empty."""
    initialize_rules()

    if Device.objects.count() == 0:
        net_info = get_system_network_info()
        devices_data = [
            {
                'ip_address': net_info['gateway'],
                'mac_address': '00:1A:2B:3C:4D:01',
                'hostname': 'gateway.netguard.local',
                'vendor': 'Cisco Systems',
                'device_type': 'Gateway',
                'status': 'Online',
                'open_ports': '53, 80, 443',
                'os_info': 'Cisco IOS-XE 17.3',
                'packet_count': 148200,
                'byte_count': 92450000,
            },
            {
                'ip_address': net_info['local_ip'] if net_info['local_ip'] != '127.0.0.1' else '192.168.1.105',
                'mac_address': '3C:52:82:11:22:33',
                'hostname': f"{net_info['hostname']} (This PC)",
                'vendor': 'Dell Inc.',
                'device_type': 'Workstation',
                'status': 'Online',
                'open_ports': '135, 445, 8000',
                'os_info': 'Microsoft Windows 10/11 Enterprise',
                'packet_count': 94500,
                'byte_count': 56300000,
            },
            {
                'ip_address': '192.168.1.120',
                'mac_address': 'B8:27:EB:4F:9A:12',
                'hostname': 'nas-backup.local',
                'vendor': 'Synology Inc.',
                'device_type': 'Server',
                'status': 'Online',
                'open_ports': '22, 80, 443, 5000',
                'os_info': 'Synology DSM 7.2 (Linux)',
                'packet_count': 41200,
                'byte_count': 324000000,
            },
            {
                'ip_address': '192.168.1.145',
                'mac_address': 'AC:DE:48:99:88:77',
                'hostname': 'lab-printer-hp.local',
                'vendor': 'HP Inc.',
                'device_type': 'IoT',
                'status': 'Idle',
                'open_ports': '80, 515, 631, 9100',
                'os_info': 'HP FutureSmart Firmware',
                'packet_count': 6400,
                'byte_count': 4100000,
            },
            {
                'ip_address': '192.168.1.170',
                'mac_address': '84:A6:C8:11:EE:55',
                'hostname': 'analyst-macbook.local',
                'vendor': 'Apple Inc.',
                'device_type': 'Laptop',
                'status': 'Online',
                'open_ports': '22, 5353',
                'os_info': 'macOS Sequoia 15.1',
                'packet_count': 23100,
                'byte_count': 18900000,
            },
            {
                'ip_address': '192.168.1.189',
                'mac_address': '02:00:00:AA:BB:CC',
                'hostname': 'unknown-guest-node.local',
                'vendor': 'Unknown OUI',
                'device_type': 'Suspicious',
                'status': 'Suspicious',
                'open_ports': 'Unfiltered Port Probes',
                'os_info': 'Linux 6.x (Nmap probe host)',
                'packet_count': 78900,
                'byte_count': 4520000,
            },
        ]

        for d in devices_data:
            Device.objects.get_or_create(ip_address=d['ip_address'], defaults=d)

    # Seed traffic snapshots if empty
    if TrafficSnapshot.objects.count() == 0:
        now = timezone.now()
        for i in range(12, -1, -1):
            t_time = now - timedelta(minutes=i * 5)
            # Baseline gentle traffic
            packets_in = random.randint(350, 750)
            packets_out = random.randint(280, 620)
            bytes_in = packets_in * random.randint(700, 1400)
            bytes_out = packets_out * random.randint(500, 1100)
            bw = round((bytes_in + bytes_out) * 8 / (1024 * 300), 2)  # kbps
            TrafficSnapshot.objects.create(
                timestamp=t_time,
                bytes_in=bytes_in,
                bytes_out=bytes_out,
                packets_in=packets_in,
                packets_out=packets_out,
                active_connections=random.randint(14, 38),
                bandwidth_kbps=bw,
                tcp_count=int((packets_in + packets_out) * 0.65),
                udp_count=int((packets_in + packets_out) * 0.25),
                icmp_count=int((packets_in + packets_out) * 0.05),
                http_count=int(packets_in * 0.2),
                https_count=int(packets_in * 0.55),
                dns_count=int(packets_in * 0.15),
                ssh_count=int(packets_in * 0.05),
                other_count=int(packets_in * 0.05),
            )

    # Seed initial Security Alert if empty
    if SecurityAlert.objects.count() == 0:
        SecurityAlert.objects.create(
            title="Rapid Port Scan Detected from 192.168.1.189",
            event_type="PORT_SCAN",
            rule_triggered="RULE-01 (Rapid Port Scan Detection)",
            severity="CRITICAL",
            source_ip="192.168.1.189",
            destination_ip="192.168.1.1",
            description="Host attempted sequential TCP SYN probes against 16 distinct ports within 8.2 seconds.",
            details="Target ports probed: 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS), 80 (HTTP), 110 (POP3), 135 (RPC), 139 (NetBIOS), 443 (HTTPS), 445 (SMB), 1433 (MSSQL), 3306 (MySQL), 3389 (RDP), 8080 (HTTP-Alt), 8443 (HTTPS-Alt).",
            packet_rate=48.5,
            port_count=16,
            timestamp=timezone.now() - timedelta(minutes=42),
            is_resolved=False,
        )
        SecurityAlert.objects.create(
            title="Excessive Connection Rate from 192.168.1.204",
            event_type="CONNECTION_BURST",
            rule_triggered="RULE-02 (Excessive Connection Rate)",
            severity="HIGH",
            source_ip="192.168.1.204",
            destination_ip="192.168.1.120",
            description="Source IP initiated 52 new socket connections within 6.4 seconds, exceeding threshold of 35.",
            details="Pattern consistent with automated credential stuffing or SYN flood against internal NAS service.",
            packet_rate=81.2,
            port_count=2,
            timestamp=timezone.now() - timedelta(minutes=95),
            is_resolved=True,
            resolved_at=timezone.now() - timedelta(minutes=60),
            resolved_by="admin",
        )
        SecurityAlert.objects.create(
            title="Suspicious Telnet / SMB Port Access Attempt",
            event_type="SUSPICIOUS_PORT",
            rule_triggered="RULE-04 (Suspicious Management Port Probing)",
            severity="MEDIUM",
            source_ip="192.168.1.189",
            destination_ip="192.168.1.145",
            description="Source host attempted inbound cleartext Telnet (Port 23) probe toward IoT printer.",
            details="Access blocked at host level; Telnet service is unencrypted and prohibited under local security policy.",
            packet_rate=6.0,
            port_count=1,
            timestamp=timezone.now() - timedelta(hours=3),
            is_resolved=True,
            resolved_at=timezone.now() - timedelta(hours=2),
            resolved_by="admin",
        )

    # Seed Activity Logs if empty
    if ActivityLog.objects.count() == 0:
        logs_data = [
            ("NetGuard Intrusion Detection Engine Initialized", "SYSTEM", "127.0.0.1", "127.0.0.1", "System kernel loaded 4 active detection rules."),
            ("Local Subnet ARP Scan Completed", "NETWORK", "192.168.1.105", "192.168.1.255", "Discovered 6 online network devices on 192.168.1.0/24."),
            ("PORT_SCAN Alert Generated for IP 192.168.1.189", "SECURITY", "192.168.1.189", "192.168.1.1", "Threshold exceeded: contacted 16 ports in 8.2s."),
            ("Security Analyst Login Authenticated", "AUTH", "192.168.1.105", "192.168.1.105", "User 'admin' signed in successfully from local console."),
            ("Traffic Snapshot Recorded", "NETWORK", "192.168.1.0/24", "192.168.1.1", "Periodic snapshot: 894 packets, 512 KB bandwidth analyzed."),
        ]
        for action, cat, src, dst, det in logs_data:
            ActivityLog.objects.create(
                action=action,
                category=cat,
                source_ip=src,
                destination_ip=dst,
                details=det,
                timestamp=timezone.now() - timedelta(minutes=random.randint(5, 120))
            )

def execute_rule_based_analysis(packet_events):
    """
    Core Rule-Based Intrusion Detection Engine (Scope D & SMART Objective 2).
    Evaluates packet batches against configured DetectionRules:
      1. Port Scan Detection (RULE-01)
      2. Excessive Connection Rate (RULE-02)
      3. Abnormal Traffic Volume (RULE-03)
      4. Suspicious Port Probing (RULE-04)
    """
    triggered_alerts = []
    start_time = time.time()

    rules = {r.code: r for r in DetectionRule.objects.filter(is_enabled=True)}

    # Group events by source_ip
    by_source = {}
    for ev in packet_events:
        src = ev.get('source_ip', 'unknown')
        if src not in by_source:
            by_source[src] = []
        by_source[src].append(ev)

    for src, events in by_source.items():
        distinct_ports = set(ev.get('destination_port') for ev in events if 'destination_port' in ev)
        total_connections = len(events)
        total_packets = sum(ev.get('packets', 1) for ev in events)
        time_span = max(0.5, ev.get('duration_seconds', 5.0))
        packet_rate = round(total_packets / time_span, 2)

        # RULE-01: Port Scan Detection
        rule_01 = rules.get('RULE-01')
        if rule_01 and len(distinct_ports) >= rule_01.threshold_value:
            rule_01.times_triggered += 1
            rule_01.save(update_fields=['times_triggered'])

            ports_sorted = sorted(list(distinct_ports))[:20]
            ports_str = ", ".join(str(p) for p in ports_sorted)
            alert = SecurityAlert.objects.create(
                title=f"Port Scan Detected from {src}",
                event_type="PORT_SCAN",
                rule_triggered=f"{rule_01.code} ({rule_01.name})",
                severity=rule_01.severity,
                source_ip=src,
                destination_ip=events[0].get('destination_ip', '192.168.1.1'),
                description=f"Host targeted {len(distinct_ports)} distinct ports within {time_span} seconds (Threshold: >= {rule_01.threshold_value}).",
                details=f"Targeted ports: {ports_str}. Packet rate: {packet_rate} pkt/s.",
                packet_rate=packet_rate,
                port_count=len(distinct_ports),
                is_resolved=False,
            )
            # Update device status
            Device.objects.filter(ip_address=src).update(status='Suspicious')
            ActivityLog.objects.create(
                action=f"PORT_SCAN Detected: {src}",
                category="SECURITY",
                source_ip=src,
                destination_ip=events[0].get('destination_ip', '192.168.1.1'),
                protocol="TCP",
                details=f"Triggered {rule_01.code}. Targeted {len(distinct_ports)} ports in {time_span}s.",
            )
            triggered_alerts.append(alert)

        # RULE-02: Excessive Connection Rate
        rule_02 = rules.get('RULE-02')
        if rule_02 and total_connections >= rule_02.threshold_value:
            rule_02.times_triggered += 1
            rule_02.save(update_fields=['times_triggered'])

            alert = SecurityAlert.objects.create(
                title=f"Excessive Connection Rate from {src}",
                event_type="CONNECTION_BURST",
                rule_triggered=f"{rule_02.code} ({rule_02.name})",
                severity=rule_02.severity,
                source_ip=src,
                destination_ip=events[0].get('destination_ip', '192.168.1.1'),
                description=f"High connection volume: {total_connections} attempts in {time_span}s (Threshold: >= {rule_02.threshold_value}).",
                details=f"Excessive connection frequency could indicate automated crawler, brute-force attack, or SYN flood.",
                packet_rate=packet_rate,
                port_count=len(distinct_ports),
                is_resolved=False,
            )
            ActivityLog.objects.create(
                action=f"CONNECTION_BURST Alert: {src}",
                category="SECURITY",
                source_ip=src,
                destination_ip=events[0].get('destination_ip', '192.168.1.1'),
                protocol="TCP",
                details=f"Triggered {rule_02.code}. Total connections: {total_connections} in {time_span}s.",
            )
            triggered_alerts.append(alert)

        # RULE-03: Abnormal Traffic Bandwidth Spike
        rule_03 = rules.get('RULE-03')
        if rule_03 and packet_rate >= rule_03.threshold_value:
            rule_03.times_triggered += 1
            rule_03.save(update_fields=['times_triggered'])

            alert = SecurityAlert.objects.create(
                title=f"Abnormal Traffic Spike from {src}",
                event_type="ABNORMAL_TRAFFIC",
                rule_triggered=f"{rule_03.code} ({rule_03.name})",
                severity=rule_03.severity,
                source_ip=src,
                destination_ip=events[0].get('destination_ip', '192.168.1.1'),
                description=f"Throughput surge detected: {packet_rate} packets/sec (Threshold: >= {rule_03.threshold_value} pkt/s).",
                details=f"Throughput exceeded local network baselines. Potential unmetered backup, data exfiltration, or flood traffic.",
                packet_rate=packet_rate,
                port_count=len(distinct_ports),
                is_resolved=False,
            )
            ActivityLog.objects.create(
                action=f"ABNORMAL_TRAFFIC Spike: {src}",
                category="SECURITY",
                source_ip=src,
                destination_ip=events[0].get('destination_ip', '192.168.1.1'),
                protocol="UDP/TCP",
                details=f"Triggered {rule_03.code}. Packet rate: {packet_rate} pkt/s.",
            )
            triggered_alerts.append(alert)

        # RULE-04: Suspicious Port Probing
        rule_04 = rules.get('RULE-04')
        risky_ports = {23: 'Telnet', 445: 'SMB', 135: 'MS-RPC', 69: 'TFTP', 31337: 'BackOrifice'}
        hit_risky = [p for p in distinct_ports if p in risky_ports]
        if rule_04 and hit_risky:
            rule_04.times_triggered += 1
            rule_04.save(update_fields=['times_triggered'])

            port_names = [f"Port {p} ({risky_ports[p]})" for p in hit_risky]
            alert = SecurityAlert.objects.create(
                title=f"Suspicious Port Access Attempt from {src}",
                event_type="SUSPICIOUS_PORT",
                rule_triggered=f"{rule_04.code} ({rule_04.name})",
                severity=rule_04.severity,
                source_ip=src,
                destination_ip=events[0].get('destination_ip', '192.168.1.1'),
                description=f"Inbound probe targeting restricted/legacy ports: {', '.join(port_names)}.",
                details="Unencrypted management or legacy RPC protocol probe observed. Violates local hardening policy.",
                packet_rate=packet_rate,
                port_count=len(hit_risky),
                is_resolved=False,
            )
            ActivityLog.objects.create(
                action=f"SUSPICIOUS_PORT Probe: {src}",
                category="SECURITY",
                source_ip=src,
                destination_ip=events[0].get('destination_ip', '192.168.1.1'),
                protocol="TCP",
                details=f"Targeted legacy/risky ports: {port_names}",
            )
            triggered_alerts.append(alert)

    elapsed_ms = max(0.05, round((time.time() - start_time) * 1000, 2))
    return {
        'alerts_triggered': triggered_alerts,
        'elapsed_ms': elapsed_ms,
        'packets_analyzed': sum(ev.get('packets', 1) for ev in packet_events),
    }

def run_controlled_scenario(scenario_key):
    """
    Executes controlled network-traffic scenarios to evaluate rule-based detection
    and document results & limitations (SMART Objective 6 & Scope D).
    """
    scenarios_def = {
        'baseline': {
            'name': 'Scenario 0: Controlled Normal Baseline Traffic',
            'description': 'Simulates standard student workstation web browsing (HTTP/HTTPS, DNS lookups, background sync).',
            'expected_verdict': 'Clean / Normal',
            'expected_rule': 'None (Pass)',
            'packets': [
                {'source_ip': '192.168.1.105', 'destination_ip': '1.1.1.1', 'destination_port': 53, 'packets': 2, 'duration_seconds': 4.0},
                {'source_ip': '192.168.1.105', 'destination_ip': '142.250.190.46', 'destination_port': 443, 'packets': 18, 'duration_seconds': 4.0},
                {'source_ip': '192.168.1.170', 'destination_ip': '17.253.144.10', 'destination_port': 443, 'packets': 14, 'duration_seconds': 4.0},
            ],
            'limitations_note': 'Normal encrypted traffic cannot inspect payload content (only IP headers and port metadata are analyzed).',
        },
        'port_scan': {
            'name': 'Scenario 1: Reconnaissance & Port Scanning (SYN Probing)',
            'description': 'Host 192.168.1.189 executes rapid TCP SYN discovery across 14 well-known ports on local gateway.',
            'expected_verdict': 'Threat Detected (CRITICAL)',
            'expected_rule': 'RULE-01 (Rapid Port Scan Detection)',
            'packets': [
                {'source_ip': '192.168.1.189', 'destination_ip': '192.168.1.1', 'destination_port': p, 'packets': 1, 'duration_seconds': 3.5}
                for p in [21, 22, 23, 25, 53, 80, 110, 135, 143, 443, 445, 1433, 3306, 8080]
            ],
            'limitations_note': 'Very slow distributed port scans below threshold (<8 ports per 15s) may evade immediate detection window.',
        },
        'connection_burst': {
            'name': 'Scenario 2: Excessive Connection Rate / SYN Flood Burst',
            'description': 'Host 192.168.1.204 initiates 48 consecutive TCP socket connections in 4.0 seconds toward local server.',
            'expected_verdict': 'Threat Detected (HIGH)',
            'expected_rule': 'RULE-02 (Excessive Connection Rate)',
            'packets': [
                {'source_ip': '192.168.1.204', 'destination_ip': '192.168.1.120', 'destination_port': 80, 'packets': 1, 'duration_seconds': 4.0}
                for _ in range(48)
            ],
            'limitations_note': 'Legitimate load testing or high-frequency API polling can trigger false positives if thresholds are too tight.',
        },
        'abnormal_traffic': {
            'name': 'Scenario 3: Abnormal Bandwidth Spike / Data Exfiltration Burst',
            'description': 'Host 192.168.1.140 pushes 650 packets in 4.0 seconds (162.5 pkt/s), drastically exceeding local baseline.',
            'expected_verdict': 'Threat Detected (HIGH)',
            'expected_rule': 'RULE-03 (Abnormal Traffic Bandwidth Spike)',
            'packets': [
                {'source_ip': '192.168.1.140', 'destination_ip': '198.51.100.22', 'destination_port': 443, 'packets': 650, 'duration_seconds': 4.0}
            ],
            'limitations_note': 'Rule-based threshold does not distinguish between legitimate large file uploads (e.g. video sync) and malicious exfiltration.',
        },
        'suspicious_port': {
            'name': 'Scenario 4: Probing Insecure Management Ports (Telnet & SMB)',
            'description': 'Host 192.168.1.189 sends probes to Telnet (23) and SMB (445) on internal subnet devices.',
            'expected_verdict': 'Threat Detected (MEDIUM)',
            'expected_rule': 'RULE-04 (Suspicious Management Port Probing)',
            'packets': [
                {'source_ip': '192.168.1.189', 'destination_ip': '192.168.1.145', 'destination_port': 23, 'packets': 3, 'duration_seconds': 5.0},
                {'source_ip': '192.168.1.189', 'destination_ip': '192.168.1.120', 'destination_port': 445, 'packets': 4, 'duration_seconds': 5.0},
            ],
            'limitations_note': 'Only targets statically blacklisted legacy ports; proprietary custom backdoor ports require updated signatures.',
        },
    }

    selected = scenarios_def.get(scenario_key, scenarios_def['port_scan'])
    result = execute_rule_based_analysis(selected['packets'])

    verdict = "THREAT DETECTED" if result['alerts_triggered'] else "NORMAL / PASS"
    return {
        'scenario_key': scenario_key,
        'name': selected['name'],
        'description': selected['description'],
        'expected_verdict': selected['expected_verdict'],
        'expected_rule': selected['expected_rule'],
        'verdict': verdict,
        'alerts_count': len(result['alerts_triggered']),
        'alerts': result['alerts_triggered'],
        'elapsed_ms': result['elapsed_ms'],
        'packets_analyzed': result['packets_analyzed'],
        'limitations_note': selected['limitations_note'],
    }
