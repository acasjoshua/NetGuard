import ipaddress
import random
import socket
import time
from datetime import timedelta
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.networks.models import Network, AllowedService, Protocol
from apps.monitoring.models import Device, TrafficStat
from apps.detection.models import DetectionRule, SecurityAlert, DetectedEvent

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
        'interface': 'Not configured (demo mode)',
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
            interface_name="Not configured",
            connection_status=Network.ConnectionStatus.DISCONNECTED,
            last_scanned_at=None,
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
    if not is_in_network_subnet(network, ip_address):
        raise ValueError(f"Device address {ip_address} is outside {network.subnet_cidr}.")

    now = timezone.now()
    device = Device.objects.filter(network=network, ip_address=ip_address).first()
    if device:
        if hostname and not device.hostname:
            device.hostname = hostname
        device.last_seen = now
        device.save(update_fields=['last_seen', 'hostname'])
        return device

    if not mac_address:
        address_bytes = ipaddress.ip_address(ip_address).packed[-5:].rjust(5, b'\x00')
        mac_address = "02:" + ":".join(f"{byte:02X}" for byte in address_bytes)

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

def is_in_network_subnet(network, ip_address):
    try:
        return ipaddress.ip_address(ip_address) in ipaddress.ip_network(
            network.subnet_cidr, strict=False
        )
    except (TypeError, ValueError):
        return False

def _sample_subnet_ips(network, count, exclude=()):
    if count <= 0:
        return []
    subnet = ipaddress.ip_network(network.subnet_cidr, strict=False)
    excluded = set()
    for address in exclude:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if parsed in subnet:
            excluded.add(str(parsed))

    addresses = []
    for address in subnet.hosts():
        address_text = str(address)
        if address_text not in excluded:
            addresses.append(address_text)
            if len(addresses) == count:
                break
    return addresses

def _events_in_rule_window(events, rule, now):
    window_seconds = rule.time_window_sec
    cutoff = now - timedelta(seconds=window_seconds)
    matching = []
    for event in events:
        timestamp = event.get('timestamp') or event.get('observed_at')
        if isinstance(timestamp, str):
            timestamp = parse_datetime(timestamp)
        if timestamp is not None:
            if timezone.is_naive(timestamp):
                timestamp = timezone.make_aware(timestamp)
            if cutoff <= timestamp <= now:
                matching.append(event)
            continue

        try:
            duration = float(event.get('duration_seconds', 5.0))
        except (TypeError, ValueError):
            continue
        if 0 <= duration <= window_seconds:
            matching.append(event)
    return matching

def seed_sample_data_if_empty():
    """Seed sample network devices, traffic stats, and alerts if database is empty."""
    network = get_default_network()
    local_ip = get_system_network_info()['local_ip']
    now = timezone.now()
    gateway_ip = (
        str(network.gateway_ip)
        if is_in_network_subnet(network, str(network.gateway_ip))
        else None
    )
    if not gateway_ip:
        candidates = _sample_subnet_ips(network, 1)
        if not candidates:
            raise ValueError(f"Network {network.subnet_cidr} has no usable host addresses.")
        gateway_ip = candidates[0]

    # 1. Devices
    if Device.objects.filter(network=network).count() == 0:
        if is_in_network_subnet(network, local_ip) and local_ip != gateway_ip:
            host_ip = local_ip
        else:
            candidates = _sample_subnet_ips(network, 1, exclude=[gateway_ip])
            host_ip = candidates[0] if candidates else gateway_ip

        demo_ips = _sample_subnet_ips(
            network, 6, exclude=[gateway_ip, host_ip]
        )
        device_specs = [
            (gateway_ip, 'gateway.netguard.local'),
            (host_ip, f"{socket.gethostname()} (This PC)"),
        ]
        demo_labels = [
            'nas-backup.local',
            'lab-printer.local',
            'analyst-laptop.local',
            'unknown-guest-node.local',
            'scanner-host.local',
            'workstation.local',
        ]
        device_specs.extend(zip(demo_ips, demo_labels))
        for index, (ip, host) in enumerate(device_specs):
            mac = f"02:00:00:00:00:{index + 1:02X}"
            get_or_create_device(
                network, ip, mac_address=mac, hostname=host, is_online=True
            )

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

        sample_ips = _sample_subnet_ips(
            network, 6, exclude=[str(network.gateway_ip), local_ip]
        )
        fallback_ip = local_ip if is_in_network_subnet(network, local_ip) else gateway_ip
        sample_ips.extend([fallback_ip] * (6 - len(sample_ips)))
        src_189 = get_or_create_device(
            network, sample_ips[3], hostname='unknown-guest-node.local'
        )
        gw = get_or_create_device(network, gateway_ip)
        nas = get_or_create_device(network, sample_ips[0], hostname='nas-backup.local')
        src_204 = get_or_create_device(
            network, sample_ips[4], hostname='scanner-host.local'
        )
        printer = get_or_create_device(
            network, sample_ips[1], hostname='lab-printer.local'
        )

        if rule_port_scan:
            alert1 = SecurityAlert.objects.create(
                network=network,
                severity=rule_port_scan.default_severity,
                status=SecurityAlert.Status.NEW,
                title=f"Sample: Port Scan from {src_189.ip_address}",
                message="Synthetic sample event with a port-scan pattern; no live probes were observed.",
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
                details="Synthetic sample event; target ports were not collected from a live network.",
                detected_at=now - timedelta(minutes=42),
            )

        if rule_conn:
            alert2 = SecurityAlert.objects.create(
                network=network,
                severity=rule_conn.default_severity,
                status=SecurityAlert.Status.RESOLVED,
                title=f"Sample: Connection Burst from {src_204.ip_address}",
                message="Synthetic sample event: the generated connection-attempt count exceeds the configured threshold.",
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
                details="Synthetic sample event for the configured connection-attempt rule.",
                detected_at=now - timedelta(minutes=95),
            )

        if rule_unauth:
            alert3 = SecurityAlert.objects.create(
                network=network,
                severity=rule_unauth.default_severity,
                status=SecurityAlert.Status.RESOLVED,
                title=f"Suspicious Telnet / SMB Port Access Attempt from {src_189.ip_address}",
                message="Synthetic sample event for an unauthorized service-port rule.",
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
                details="Synthetic sample event for an unauthorized service-port rule.",
                detected_at=now - timedelta(hours=3),
            )

def execute_rule_based_analysis(packet_events):
    """
    Evaluate one captured or synthetic batch against enabled database rules.
    """
    triggered_alerts = []
    start_time = time.time()
    now = timezone.now()
    network = get_default_network()
    packet_events = list(packet_events)
    eligible_events = [
        event for event in packet_events
        if is_in_network_subnet(network, event.get('source_ip'))
    ]

    rules = {r.code: r for r in DetectionRule.objects.filter(is_enabled=True)}
    allowed_ports = set(AllowedService.objects.filter(network=network).values_list('port', flat=True))
    if not allowed_ports:
        allowed_ports = {80, 443, 53, 22}

    by_source = {}
    for ev in eligible_events:
        src = str(ipaddress.ip_address(ev['source_ip']))
        if src not in by_source:
            by_source[src] = []
        by_source[src].append(ev)

    for src, events in by_source.items():
        dst_ip = events[0].get('destination_ip', network.gateway_ip)
        default_duration = max(
            (float(event.get('duration_seconds', 5.0)) for event in events),
            default=5.0,
        )
        time_span = max(0.5, default_duration)
        total_packets = sum(int(ev.get('packets', 1)) for ev in events)
        packet_rate = round(total_packets / time_span, 2)

        src_dev = get_or_create_device(network, src)
        dst_dev = (
            get_or_create_device(network, dst_ip)
            if dst_ip and is_in_network_subnet(network, dst_ip)
            else None
        )

        rule_port = rules.get('PORT_SCAN')
        port_events = _events_in_rule_window(events, rule_port, now) if rule_port else []
        distinct_ports = {
            int(ev['destination_port'])
            for ev in port_events
            if ev.get('destination_port') is not None
        }
        if rule_port and port_events and len(distinct_ports) >= rule_port.threshold:
            ports_str = ", ".join(str(p) for p in sorted(list(distinct_ports))[:20])
            alert = SecurityAlert.objects.create(
                network=network,
                severity=rule_port.default_severity,
                status=SecurityAlert.Status.NEW,
                title=f"Port Scan Detected from {src}",
                message=f"Synthetic events targeted {len(distinct_ports)} distinct ports within {rule_port.time_window_sec}s (Threshold: >= {rule_port.threshold}). Ports: {ports_str}.",
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
            if src_dev:
                src_dev.is_online = True
                src_dev.save(update_fields=['is_online'])
            triggered_alerts.append(alert)

        # HOST_SCAN counts distinct local destinations reached on the same port.
        rule_host = rules.get('HOST_SCAN')
        host_events = _events_in_rule_window(events, rule_host, now) if rule_host else []
        hosts_by_port = {}
        for event in host_events:
            target_ip = event.get('destination_ip')
            port = event.get('destination_port')
            if (
                target_ip
                and port is not None
                and is_in_network_subnet(network, target_ip)
            ):
                hosts_by_port.setdefault(int(port), set()).add(str(target_ip))
        matching_host_scans = {
            port: hosts
            for port, hosts in hosts_by_port.items()
            if rule_host and len(hosts) >= rule_host.threshold
        }
        if rule_host and matching_host_scans:
            scanned_hosts = set().union(*matching_host_scans.values())
            alert = SecurityAlert.objects.create(
                network=network,
                severity=rule_host.default_severity,
                status=SecurityAlert.Status.NEW,
                title=f"Host Scan Detected from {src}",
                message=(
                    f"Host probed {len(scanned_hosts)} distinct local destinations "
                    f"within {rule_host.time_window_sec}s on a shared port."
                ),
            )
            for port, target_ips in matching_host_scans.items():
                for target_ip in target_ips:
                    target_device = get_or_create_device(network, target_ip)
                    DetectedEvent.objects.create(
                        network=network,
                        rule=rule_host,
                        source_device=src_dev,
                        target_device=target_device,
                        alert=alert,
                        port=port,
                        protocol=Protocol.TCP,
                        event_count=len(target_ips),
                        details=(
                            f"At least {rule_host.threshold} local hosts were "
                            f"probed on port {port} within the configured window."
                        ),
                        detected_at=now,
                    )
            triggered_alerts.append(alert)

        rule_conn = rules.get('CONN_ATTEMPT')
        connection_events = (
            _events_in_rule_window(events, rule_conn, now) if rule_conn else []
        )
        connection_count = sum(
            int(event.get('connection_attempts', event.get('event_count', 1)))
            for event in connection_events
        )
        if rule_conn and connection_events and connection_count >= rule_conn.threshold:
            alert = SecurityAlert.objects.create(
                network=network,
                severity=rule_conn.default_severity,
                status=SecurityAlert.Status.NEW,
                title=f"Excessive Connection Rate from {src}",
                message=(
                    f"High connection volume: {connection_count} attempts within "
                    f"{rule_conn.time_window_sec}s (Threshold: >= {rule_conn.threshold})."
                ),
            )
            target_port = connection_events[0].get('destination_port') if connection_events else 80
            DetectedEvent.objects.create(
                network=network,
                rule=rule_conn,
                source_device=src_dev,
                target_device=dst_dev,
                alert=alert,
                port=target_port,
                protocol=Protocol.TCP,
                event_count=connection_count,
                details="Connection-attempt count exceeded the configured rule threshold.",
                detected_at=now,
            )
            triggered_alerts.append(alert)

        rule_dos = rules.get('DOS_BANDWIDTH')
        bandwidth_events = _events_in_rule_window(events, rule_dos, now) if rule_dos else []
        supplied_bandwidth = sum(
            int(event.get('bandwidth_bps', 0) or 0) for event in bandwidth_events
        )
        bandwidth_packets = sum(
            int(event.get('packets', 1)) for event in bandwidth_events
        )
        bandwidth_span = max(
            0.5,
            max(
                (float(event.get('duration_seconds', 5.0)) for event in bandwidth_events),
                default=time_span,
            ),
        )
        bandwidth_bps = supplied_bandwidth or int(
            (bandwidth_packets * 1500 * 8) / bandwidth_span
        )
        if rule_dos and bandwidth_events and bandwidth_bps >= rule_dos.threshold:
            alert = SecurityAlert.objects.create(
                network=network,
                severity=rule_dos.default_severity,
                status=SecurityAlert.Status.NEW,
                title=f"Abnormal Traffic Spike from {src}",
                message=(
                    f"Throughput reached {bandwidth_bps} bps within "
                    f"{rule_dos.time_window_sec}s (Threshold: >= {rule_dos.threshold} bps)."
                ),
            )
            DetectedEvent.objects.create(
                network=network,
                rule=rule_dos,
                source_device=src_dev,
                target_device=dst_dev,
                alert=alert,
                port=events[0].get('destination_port') if events else 443,
                protocol=Protocol.TCP,
                event_count=bandwidth_packets,
                details=(
                    f"Observed rate: {bandwidth_bps} bps; packet rate "
                    f"{packet_rate} packets/s."
                ),
                detected_at=now,
            )
            triggered_alerts.append(alert)

        rule_unauth = rules.get('UNAUTH_SERVICE')
        unauth_events = _events_in_rule_window(events, rule_unauth, now) if rule_unauth else []
        unauth_ports = {
            int(ev['destination_port'])
            for ev in unauth_events
            if ev.get('destination_port') is not None
            and int(ev['destination_port']) not in allowed_ports
        }
        if rule_unauth and unauth_events and len(unauth_ports) >= rule_unauth.threshold:
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
        'packets_analyzed': sum(int(ev.get('packets', 1)) for ev in eligible_events),
        'events_ignored_outside_subnet': len(packet_events) - len(eligible_events),
    }

def run_controlled_scenario(scenario_key):
    """
    Evaluate generated demonstration traffic against the configured rules.
    """
    network = get_default_network()
    all_rules = {
        rule.code: rule
        for rule in DetectionRule.objects.all()
    }
    enabled_rules = {
        code: rule for code, rule in all_rules.items() if rule.is_enabled
    }

    def rule_threshold(code, default):
        rule = all_rules.get(code)
        return rule.threshold if rule else default

    host_threshold = rule_threshold('HOST_SCAN', 10)
    scenario_hosts = _sample_subnet_ips(
        network,
        max(8, host_threshold + 2),
        exclude=[str(network.gateway_ip)],
    )
    if not scenario_hosts:
        raise ValueError(f"Network {network.subnet_cidr} has no usable host addresses.")

    source_ip = scenario_hosts[0]
    secondary_source_ip = scenario_hosts[1] if len(scenario_hosts) > 1 else source_ip
    internal_target = scenario_hosts[2] if len(scenario_hosts) > 2 else str(network.gateway_ip)
    gateway_ip = (
        str(network.gateway_ip)
        if is_in_network_subnet(network, str(network.gateway_ip))
        else internal_target
    )
    host_scan_targets = scenario_hosts[1:max(2, host_threshold + 1)]
    port_threshold = max(1, rule_threshold('PORT_SCAN', 15))
    connection_threshold = max(1, rule_threshold('CONN_ATTEMPT', 20))
    bandwidth_threshold = max(1, rule_threshold('DOS_BANDWIDTH', 50_000_000))
    unauthorized_threshold = max(1, rule_threshold('UNAUTH_SERVICE', 1))
    port_window = all_rules['PORT_SCAN'].time_window_sec if 'PORT_SCAN' in all_rules else 60
    host_window = all_rules['HOST_SCAN'].time_window_sec if 'HOST_SCAN' in all_rules else 60
    connection_window = all_rules['CONN_ATTEMPT'].time_window_sec if 'CONN_ATTEMPT' in all_rules else 60
    bandwidth_window = all_rules['DOS_BANDWIDTH'].time_window_sec if 'DOS_BANDWIDTH' in all_rules else 10
    unauth_window = all_rules['UNAUTH_SERVICE'].time_window_sec if 'UNAUTH_SERVICE' in all_rules else 60
    allowed_ports = set(
        AllowedService.objects.filter(network=network).values_list('port', flat=True)
    )
    unauthorized_ports = [
        port for port in range(20000, 65536) if port not in allowed_ports
    ][:unauthorized_threshold]
    host_scan_possible = bool(host_scan_targets) and len(host_scan_targets) >= host_threshold

    scenarios_def = {
        'baseline': {
            'name': 'Scenario 0: Controlled Normal Baseline Traffic',
            'description': 'Synthetic HTTP/HTTPS and DNS-like activity generated for rule testing; no live traffic is captured.',
            'expected_verdict': 'Clean / Normal',
            'expected_rule': 'None (Pass)',
            'packets': [
                {'source_ip': source_ip, 'destination_ip': '1.1.1.1', 'destination_port': 53, 'packets': 2, 'duration_seconds': 4.0},
                {'source_ip': source_ip, 'destination_ip': '142.250.190.46', 'destination_port': 443, 'packets': 18, 'duration_seconds': 4.0},
                {'source_ip': secondary_source_ip, 'destination_ip': '17.253.144.10', 'destination_port': 443, 'packets': 14, 'duration_seconds': 4.0},
            ],
            'limitations_note': 'This is generated test data, not a capture of actual encrypted or unencrypted traffic.',
        },
        'port_scan': {
            'name': 'Scenario 1: Reconnaissance & Port Scanning (SYN Probing)',
            'description': f'A synthetic local host probes {port_threshold} distinct ports within the configured rule window.',
            'expected_verdict': 'Threat Detected (MEDIUM / CRITICAL)',
            'expected_rule': 'PORT_SCAN (Port scanning)',
            'packets': [
                {
                    'source_ip': source_ip,
                    'destination_ip': gateway_ip,
                    'destination_port': port,
                    'packets': 1,
                    'duration_seconds': min(3.5, float(port_window)),
                }
                for port in range(2000, 2000 + port_threshold)
            ],
            'limitations_note': 'The generated event batch tests the configured threshold and time window; it is not live network traffic.',
        },
        'host_scan': {
            'name': 'Scenario 2: Local Host Scan',
            'description': f'A synthetic local host probes the same port across {len(host_scan_targets)} local destinations.',
            'expected_verdict': (
                'Threat Detected (MEDIUM / CRITICAL)'
                if host_scan_possible else 'Insufficient local hosts to meet threshold'
            ),
            'expected_rule': 'HOST_SCAN (Host scanning)',
            'packets': [
                {
                    'source_ip': source_ip,
                    'destination_ip': target_ip,
                    'destination_port': 8080,
                    'packets': 1,
                    'duration_seconds': min(4.0, float(host_window)),
                }
                for target_ip in host_scan_targets
            ],
            'limitations_note': (
                'This scenario is synthetic. A subnet with fewer usable hosts than the '
                'configured threshold cannot demonstrate a positive host-scan result.'
            ),
        },
        'connection_burst': {
            'name': 'Scenario 3: Excessive Connection Rate',
            'description': f'A synthetic local host generates {connection_threshold} connection attempts within the configured rule window.',
            'expected_verdict': 'Threat Detected (LOW / HIGH)',
            'expected_rule': 'CONN_ATTEMPT (Connection attempts)',
            'packets': [
                {
                    'source_ip': secondary_source_ip,
                    'destination_ip': internal_target,
                    'destination_port': 80,
                    'packets': 1,
                    'duration_seconds': min(4.0, float(connection_window)),
                }
                for _ in range(connection_threshold)
            ],
            'limitations_note': 'Generated connection counts do not represent successful or failed live socket connections.',
        },
        'abnormal_traffic': {
            'name': 'Scenario 4: Abnormal Bandwidth Rate',
            'description': f'A synthetic local host reports a bandwidth rate at the configured {bandwidth_threshold} bps threshold.',
            'expected_verdict': 'Threat Detected (HIGH)',
            'expected_rule': 'DOS_BANDWIDTH (Denial of service bandwidth)',
            'packets': [
                {
                    'source_ip': source_ip,
                    'destination_ip': '198.51.100.22',
                    'destination_port': 443,
                    'packets': 650,
                    'bandwidth_bps': bandwidth_threshold,
                    'duration_seconds': min(4.0, float(bandwidth_window)),
                }
            ],
            'limitations_note': 'The bandwidth value is generated test input and does not represent measured throughput.',
        },
        'suspicious_port': {
            'name': 'Scenario 5: Unauthorized Service Ports',
            'description': f'A synthetic local host probes {len(unauthorized_ports)} ports outside the configured allowed-service list.',
            'expected_verdict': 'Threat Detected (HIGH)',
            'expected_rule': 'UNAUTH_SERVICE (Unauthorized network service)',
            'packets': [
                {
                    'source_ip': source_ip,
                    'destination_ip': internal_target,
                    'destination_port': port,
                    'packets': 1,
                    'duration_seconds': min(5.0, float(unauth_window)),
                }
                for port in unauthorized_ports
            ],
            'limitations_note': 'Generated test events use ports absent from the configured allowed-service list.',
        },
    }

    selected = scenarios_def.get(scenario_key, scenarios_def['port_scan'])
    scenario_rule = {
        'baseline': None,
        'port_scan': 'PORT_SCAN',
        'host_scan': 'HOST_SCAN',
        'connection_burst': 'CONN_ATTEMPT',
        'abnormal_traffic': 'DOS_BANDWIDTH',
        'suspicious_port': 'UNAUTH_SERVICE',
    }.get(scenario_key, 'PORT_SCAN')
    if scenario_rule and scenario_rule not in enabled_rules:
        selected = dict(selected)
        selected['expected_verdict'] = 'Not evaluated (rule disabled)'
        selected['expected_rule'] = f'{scenario_rule} is disabled'
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
        'events_ignored_outside_subnet': result['events_ignored_outside_subnet'],
        'limitations_note': selected['limitations_note'],
    }
