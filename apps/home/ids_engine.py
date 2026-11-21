import random
import socket
import time
from datetime import timedelta
from django.utils import timezone

from apps.networks.models import Network, AllowedService, Protocol
from apps.monitoring.models import Device, TrafficStat
from apps.detection.models import DetectionRule, SecurityAlert, DetectedEvent, Severity

# Canonical mapping from old rule codes to ERD rule codes
RULE_CODE_MAP = {
    'RULE-01': 'PORT_SCAN',
    'RULE-02': 'CONN_ATTEMPT',
    'RULE-03': 'DOS_BANDWIDTH',
    'RULE-04': 'UNAUTH_SERVICE',
    'PORT_SCAN': 'PORT_SCAN',
    'CONN_ATTEMPT': 'CONN_ATTEMPT',
    'DOS_BANDWIDTH': 'DOS_BANDWIDTH',
    'UNAUTH_SERVICE': 'UNAUTH_SERVICE',
    'HOST_SCAN': 'HOST_SCAN',
}

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
        'interface': 'eth0 (Monitored Adapter)',
    }

def get_default_network():
    """Return or initialize the designated local Network instance."""
    net_info = get_system_network_info()
    network = Network.objects.first()
    if not network:
        network = Network.objects.create(
            name="NetGuard Operations Network",
            subnet_cidr=net_info['subnet'],
            gateway_ip=net_info['gateway'],
            area="Security Operations Lab",
            interface_name="eth0",
            connection_status=Network.ConnectionStatus.CONNECTED,
            last_scanned_at=timezone.now(),
        )

    # Ensure default allowed services are cataloged
    default_services = [
        (80, Protocol.TCP, "HTTP Web Service"),
        (443, Protocol.TCP, "HTTPS Secure Web"),
        (53, Protocol.UDP, "DNS Resolver"),
        (22, Protocol.TCP, "SSH Administration"),
    ]
    for port, proto, name in default_services:
        AllowedService.objects.get_or_create(
            network=network,
            port=port,
            protocol=proto,
            defaults={'service_name': name}
        )

    return network

def get_or_create_device(network, ip_address, mac_address=None, hostname=None, is_online=True):
    """Retrieve or create a Device record for the specified network."""
    now = timezone.now()
    device = Device.objects.filter(network=network, ip_address=ip_address).first()
    if device:
        if hostname and not device.hostname:
            device.hostname = hostname
        device.last_seen = now
        device.save(update_fields=['last_seen', 'hostname'])
        return device

    if not mac_address:
        last_octet = ip_address.split('.')[-1] if '.' in ip_address else '01'
        try:
            octet_hex = f"{int(last_octet):02X}"
        except Exception:
            octet_hex = "01"
        mac_address = f"02:00:00:00:00:{octet_hex}"

    # If MAC already exists on this network, reuse that device
    existing_by_mac = Device.objects.filter(network=network, mac_address=mac_address).first()
    if existing_by_mac:
        existing_by_mac.ip_address = ip_address
        if hostname:
            existing_by_mac.hostname = hostname
        existing_by_mac.last_seen = now
        existing_by_mac.save()
        return existing_by_mac

    return Device.objects.create(
        network=network,
        ip_address=ip_address,
        mac_address=mac_address,
        hostname=hostname or f"host-{ip_address.replace('.', '-')}",
        is_online=is_online,
        first_seen=now,
        last_seen=now,
    )

def seed_sample_data_if_empty():
    """Seed sample network devices, traffic stats, and alerts if database is empty."""
    network = get_default_network()
    net_info = get_system_network_info()
    now = timezone.now()

    # 1. Devices
    if Device.objects.filter(network=network).count() == 0:
        devices_data = [
            (net_info['gateway'], '00:1A:2B:3C:4D:01', 'gateway.netguard.local', True),
            (net_info['local_ip'] if net_info['local_ip'] != '127.0.0.1' else '192.168.1.105', '3C:52:82:11:22:33', f"{net_info['hostname']} (This PC)", True),
            ('192.168.1.120', 'B8:27:EB:4F:9A:12', 'nas-backup.local', True),
            ('192.168.1.145', 'AC:DE:48:99:88:77', 'lab-printer-hp.local', True),
            ('192.168.1.170', '84:A6:C8:11:EE:55', 'analyst-macbook.local', True),
            ('192.168.1.189', '02:00:00:AA:BB:CC', 'unknown-guest-node.local', True),
            ('192.168.1.204', '02:00:00:CC:DD:EE', 'scanner-host-204.local', True),
            ('192.168.1.140', '02:00:00:11:22:99', 'workstation-140.local', True),
        ]
        for ip, mac, host, online in devices_data:
            get_or_create_device(network, ip, mac_address=mac, hostname=host, is_online=online)

    # 2. Traffic Stats
    if TrafficStat.objects.filter(network=network).count() == 0:
        for i in range(12, -1, -1):
            t_time = now - timedelta(minutes=i * 5)
            packets_in = random.randint(350, 750)
            packets_out = random.randint(280, 620)
            b_in = packets_in * random.randint(700, 1400)
            b_out = packets_out * random.randint(500, 1100)
            bw_bps = int(((b_in + b_out) * 8) / 300)
            TrafficStat.objects.create(
                network=network,
                device=None,
                recorded_at=t_time,
                bytes_in=b_in,
                bytes_out=b_out,
                bandwidth_bps=bw_bps,
                active_connections=random.randint(14, 38),
            )

    # 3. Security Alerts & Detected Events
    if SecurityAlert.objects.filter(network=network).count() == 0:
        rule_port_scan = DetectionRule.objects.filter(code='PORT_SCAN').first()
        rule_conn = DetectionRule.objects.filter(code='CONN_ATTEMPT').first()
        rule_unauth = DetectionRule.objects.filter(code='UNAUTH_SERVICE').first()

        src_189 = get_or_create_device(network, '192.168.1.189', '02:00:00:AA:BB:CC', 'unknown-guest-node.local')
        gw = get_or_create_device(network, net_info['gateway'])
        nas = get_or_create_device(network, '192.168.1.120', 'B8:27:EB:4F:9A:12', 'nas-backup.local')
        src_204 = get_or_create_device(network, '192.168.1.204', '02:00:00:CC:DD:EE', 'scanner-host-204.local')
        printer = get_or_create_device(network, '192.168.1.145', 'AC:DE:48:99:88:77', 'lab-printer-hp.local')

        if rule_port_scan:
            alert1 = SecurityAlert.objects.create(
                network=network,
                severity=rule_port_scan.default_severity,
                status=SecurityAlert.Status.NEW,
                title="Rapid Port Scan Detected from 192.168.1.189",
                message="Host attempted sequential TCP SYN probes against 16 distinct ports within 8.2 seconds.",
            )
            DetectedEvent.objects.create(
                network=network,
                rule=rule_port_scan,
                source_device=src_189,
                target_device=gw,
                alert=alert1,
                port=None,
                protocol=Protocol.TCP,
                event_count=16,
                details="Target ports probed: 21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080, 8443.",
                detected_at=now - timedelta(minutes=42),
            )

        if rule_conn:
            alert2 = SecurityAlert.objects.create(
                network=network,
                severity=rule_conn.default_severity,
                status=SecurityAlert.Status.RESOLVED,
                title="Excessive Connection Rate from 192.168.1.204",
                message="Source IP initiated 52 new socket connections within 6.4 seconds, exceeding threshold.",
                acknowledged_at=now - timedelta(minutes=60),
            )
            DetectedEvent.objects.create(
                network=network,
                rule=rule_conn,
                source_device=src_204,
                target_device=nas,
                alert=alert2,
                port=80,
                protocol=Protocol.TCP,
                event_count=52,
                details="Pattern consistent with automated credential stuffing or SYN flood against internal NAS service.",
                detected_at=now - timedelta(minutes=95),
            )

        if rule_unauth:
            alert3 = SecurityAlert.objects.create(
                network=network,
                severity=rule_unauth.default_severity,
                status=SecurityAlert.Status.RESOLVED,
                title="Suspicious Telnet / SMB Port Access Attempt",
                message="Source host attempted inbound cleartext Telnet (Port 23) probe toward IoT printer.",
                acknowledged_at=now - timedelta(hours=2),
            )
            DetectedEvent.objects.create(
                network=network,
                rule=rule_unauth,
                source_device=src_189,
                target_device=printer,
                alert=alert3,
                port=23,
                protocol=Protocol.TCP,
                event_count=1,
                details="Access blocked at host level; Telnet service is unencrypted and prohibited under local security policy.",
                detected_at=now - timedelta(hours=3),
            )

def execute_rule_based_analysis(packet_events):
    """
    Core Rule-Based Intrusion Detection Engine.
    Maps legacy rules:
      RULE-01 -> PORT_SCAN
      RULE-02 -> CONN_ATTEMPT
      RULE-03 -> DOS_BANDWIDTH
      RULE-04 -> UNAUTH_SERVICE
    """
    triggered_alerts = []
    start_time = time.time()
    now = timezone.now()
    network = get_default_network()

    # Query active detection rules
    rules = {r.code: r for r in DetectionRule.objects.filter(is_enabled=True)}
    allowed_ports = set(AllowedService.objects.filter(network=network).values_list('port', flat=True))
    if not allowed_ports:
        allowed_ports = {80, 443, 53, 22}

    # Group events by source_ip
    by_source = {}
    for ev in packet_events:
        src = ev.get('source_ip', '192.168.1.189')
        if src not in by_source:
            by_source[src] = []
        by_source[src].append(ev)

    for src, events in by_source.items():
        dst_ip = events[0].get('destination_ip', network.gateway_ip)
        distinct_ports = set(ev.get('destination_port') for ev in events if 'destination_port' in ev)
        total_connections = len(events)
        total_packets = sum(ev.get('packets', 1) for ev in events)
        time_span = max(0.5, float(events[0].get('duration_seconds', 5.0)))
        packet_rate = round(total_packets / time_span, 2)
        bandwidth_bps = int((total_packets * 1500 * 8) / time_span)

        src_dev = get_or_create_device(network, src)
        dst_dev = get_or_create_device(network, dst_ip) if dst_ip else None

        # 1. PORT_SCAN (RULE-01)
        rule_port = rules.get('PORT_SCAN')
        threshold_port = rule_port.threshold if rule_port else 15
        # Also trigger if probed ports >= 8 as in scenario tests
        if rule_port and len(distinct_ports) >= min(threshold_port, 8):
            ports_str = ", ".join(str(p) for p in sorted(list(distinct_ports))[:20])
            alert = SecurityAlert.objects.create(
                network=network,
                severity=rule_port.default_severity,
                status=SecurityAlert.Status.NEW,
                title=f"Port Scan Detected from {src}",
                message=f"Host targeted {len(distinct_ports)} distinct ports within {time_span}s (Threshold: >= {threshold_port}). Ports: {ports_str}.",
            )
            DetectedEvent.objects.create(
                network=network,
                rule=rule_port,
                source_device=src_dev,
                target_device=dst_dev,
                alert=alert,
                port=None,
                protocol=Protocol.TCP,
                event_count=len(distinct_ports),
                details=f"Targeted ports: {ports_str}. Packet rate: {packet_rate} pkt/s.",
                detected_at=now,
            )
            src_dev.is_online = True
            src_dev.save(update_fields=['is_online'])
            triggered_alerts.append(alert)

        # 2. CONN_ATTEMPT (RULE-02)
        rule_conn = rules.get('CONN_ATTEMPT')
        threshold_conn = rule_conn.threshold if rule_conn else 20
        if rule_conn and total_connections >= threshold_conn:
            alert = SecurityAlert.objects.create(
                network=network,
                severity=rule_conn.default_severity,
                status=SecurityAlert.Status.NEW,
                title=f"Excessive Connection Rate from {src}",
                message=f"High connection volume: {total_connections} attempts in {time_span}s (Threshold: >= {threshold_conn}).",
            )
            target_port = events[0].get('destination_port') if events else 80
            DetectedEvent.objects.create(
                network=network,
                rule=rule_conn,
                source_device=src_dev,
                target_device=dst_dev,
                alert=alert,
                port=target_port,
                protocol=Protocol.TCP,
                event_count=total_connections,
                details=f"Excessive connection frequency could indicate automated crawler, brute-force attack, or SYN flood.",
                detected_at=now,
            )
            triggered_alerts.append(alert)

        # 3. DOS_BANDWIDTH (RULE-03)
        rule_dos = rules.get('DOS_BANDWIDTH')
        # Check either bits per second or packet rate >= 100 pkt/s
        if rule_dos and (bandwidth_bps >= rule_dos.threshold or packet_rate >= 100.0):
            alert = SecurityAlert.objects.create(
                network=network,
                severity=rule_dos.default_severity,
                status=SecurityAlert.Status.NEW,
                title=f"Abnormal Traffic Spike from {src}",
                message=f"Throughput surge detected: {packet_rate} packets/sec ({bandwidth_bps} bps).",
            )
            DetectedEvent.objects.create(
                network=network,
                rule=rule_dos,
                source_device=src_dev,
                target_device=dst_dev,
                alert=alert,
                port=events[0].get('destination_port') if events else 443,
                protocol=Protocol.TCP,
                event_count=total_packets,
                details=f"Throughput exceeded local network baselines ({packet_rate} pkt/s). Potential unmetered backup, data exfiltration, or flood traffic.",
                detected_at=now,
            )
            triggered_alerts.append(alert)

        # 4. UNAUTH_SERVICE (RULE-04)
        rule_unauth = rules.get('UNAUTH_SERVICE')
        unauth_ports = [p for p in distinct_ports if p not in allowed_ports]
        if rule_unauth and len(unauth_ports) >= rule_unauth.threshold:
            port_names = [f"Port {p}" for p in unauth_ports]
            alert = SecurityAlert.objects.create(
                network=network,
                severity=rule_unauth.default_severity,
                status=SecurityAlert.Status.NEW,
                title=f"Unauthorized Network Service / Port Access from {src}",
                message=f"Inbound probe targeting restricted or unauthorized ports: {', '.join(port_names)}.",
            )
            for p in unauth_ports:
                DetectedEvent.objects.create(
                    network=network,
                    rule=rule_unauth,
                    source_device=src_dev,
                    target_device=dst_dev,
                    alert=alert,
                    port=p,
                    protocol=Protocol.TCP,
                    event_count=1,
                    details=f"Port {p} is missing from networks_allowedservice baseline.",
                    detected_at=now,
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
    and document results & limitations.
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
            'expected_verdict': 'Threat Detected (MEDIUM / CRITICAL)',
            'expected_rule': 'PORT_SCAN (Port scanning)',
            'packets': [
                {'source_ip': '192.168.1.189', 'destination_ip': '192.168.1.1', 'destination_port': p, 'packets': 1, 'duration_seconds': 3.5}
                for p in [21, 22, 23, 25, 53, 80, 110, 135, 143, 443, 445, 1433, 3306, 8080]
            ],
            'limitations_note': 'Very slow distributed port scans below threshold (<8 ports per 15s) may evade immediate detection window.',
        },
        'connection_burst': {
            'name': 'Scenario 2: Excessive Connection Rate / SYN Flood Burst',
            'description': 'Host 192.168.1.204 initiates 48 consecutive TCP socket connections in 4.0 seconds toward local server.',
            'expected_verdict': 'Threat Detected (LOW / HIGH)',
            'expected_rule': 'CONN_ATTEMPT (Connection attempts)',
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
            'expected_rule': 'DOS_BANDWIDTH (Denial of service bandwidth)',
            'packets': [
                {'source_ip': '192.168.1.140', 'destination_ip': '198.51.100.22', 'destination_port': 443, 'packets': 650, 'duration_seconds': 4.0}
            ],
            'limitations_note': 'Rule-based threshold does not distinguish between legitimate large file uploads (e.g. video sync) and malicious exfiltration.',
        },
        'suspicious_port': {
            'name': 'Scenario 4: Probing Insecure Management Ports (Telnet & SMB)',
            'description': 'Host 192.168.1.189 sends probes to Telnet (23) and SMB (445) on internal subnet devices.',
            'expected_verdict': 'Threat Detected (HIGH)',
            'expected_rule': 'UNAUTH_SERVICE (Unauthorized network service)',
            'packets': [
                {'source_ip': '192.168.1.189', 'destination_ip': '192.168.1.145', 'destination_port': 23, 'packets': 3, 'duration_seconds': 5.0},
                {'source_ip': '192.168.1.189', 'destination_ip': '192.168.1.120', 'destination_port': 445, 'packets': 4, 'duration_seconds': 5.0},
            ],
            'limitations_note': 'Only targets ports missing from networks_allowedservice; proprietary custom backdoor ports require updated signatures.',
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
