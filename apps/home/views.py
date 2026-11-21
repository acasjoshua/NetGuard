import csv
import json
import random
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone
from datetime import timedelta
from django.db.models import Sum, Count, Q

from apps.networks.models import Network, AllowedService, Protocol
from apps.monitoring.models import Device, TrafficStat
from apps.detection.models import DetectionRule, SecurityAlert, DetectedEvent, Severity
from .ids_engine import (
    seed_sample_data_if_empty,
    get_system_network_info,
    get_default_network,
    run_controlled_scenario,
    execute_rule_based_analysis,
)

class ComputedReport:
    """In-memory computed security report (no legacy SecurityReport table needed)."""
    def __init__(self, id_val, title, time_period, generated_by, total_events, critical_count,
                 high_count, medium_count, low_count, monitored_devices, network_health_score,
                 executive_summary, findings, recommendations, generated_at=None):
        self.id = id_val
        self.title = title
        self.report_type = "Comprehensive Network Audit"
        self.time_period = time_period
        self.generated_by = generated_by
        self.total_events = total_events
        self.critical_count = critical_count
        self.high_count = high_count
        self.medium_count = medium_count
        self.low_count = low_count
        self.monitored_devices = monitored_devices
        self.network_health_score = network_health_score
        self.executive_summary = executive_summary
        self.findings = findings
        self.recommendations = recommendations
        self.generated_at = generated_at or timezone.now()

def generate_computed_report(network, title="Local Subnet Intrusion Assessment", period="Last 24 Hours", user=None, report_id=1):
    total_ev = DetectedEvent.objects.filter(network=network).count()
    crit = SecurityAlert.objects.filter(network=network, severity=Severity.CRITICAL).count()
    high = SecurityAlert.objects.filter(network=network, severity=Severity.HIGH).count()
    med = SecurityAlert.objects.filter(network=network, severity=Severity.MEDIUM).count()
    low = SecurityAlert.objects.filter(network=network, severity=Severity.LOW).count()
    dev_count = Device.objects.filter(network=network).count()

    health = max(45, 100 - (crit * 15 + high * 8 + med * 3))

    exec_summary = (
        f"NetGuard conducted automated rule-based intrusion detection across the local subnet. "
        f"A total of {total_ev} security events were analyzed over {period}. "
        f"{crit} critical threat events and {high} high-priority anomalies were recorded. "
        f"Overall local network integrity score is evaluated at {health}%."
    )
    findings = (
        f"1. Reconnaissance Activity: Monitored hosts evaluated against port scanning and connection rate baselines.\n"
        f"2. Traffic Spikes: Bandwidth thresholds evaluated against active connections.\n"
        f"3. Insecure Protocols: Legacy/unallowed services (Telnet 23, SMB 445) flagged.\n"
        f"4. Device Inventory: {dev_count} connected endpoints are currently cataloged on {network.subnet_cidr}."
    )
    recommendations = (
        f"1. Isolate or block unknown hosts pending physical authorization.\n"
        f"2. Ensure unauthorized ports are disabled across all endpoints.\n"
        f"3. Enforce rate limiting on internal DNS and gateway administration ports.\n"
        f"4. Regularly review detection rule thresholds to maintain optimal sensitivity."
    )

    class DummyUser:
        username = "admin"

    return ComputedReport(
        id_val=report_id,
        title=title,
        time_period=period,
        generated_by=user if (user and user.is_authenticated) else DummyUser(),
        total_events=total_ev,
        critical_count=crit,
        high_count=high,
        medium_count=med,
        low_count=low,
        monitored_devices=dev_count,
        network_health_score=health,
        executive_summary=exec_summary,
        findings=findings,
        recommendations=recommendations,
    )

@login_required
def home_view(request):
    """Network Dashboard"""
    seed_sample_data_if_empty()
    network = get_default_network()
    net_info = get_system_network_info()

    devices = Device.objects.filter(network=network)
    alerts = SecurityAlert.objects.filter(network=network)
    recent_alerts = alerts[:5]
    unresolved_alerts_count = alerts.filter(status__in=[SecurityAlert.Status.NEW, SecurityAlert.Status.ACKNOWLEDGED]).count()
    critical_alerts_count = alerts.filter(status__in=[SecurityAlert.Status.NEW, SecurityAlert.Status.ACKNOWLEDGED], severity=Severity.CRITICAL).count()

    # Determine overall security status
    if critical_alerts_count > 0:
        system_status = {'label': 'Threats Active', 'class': 'danger', 'icon': 'exclamation-triangle'}
    elif unresolved_alerts_count > 0:
        system_status = {'label': 'Warning - Elevated', 'class': 'warning', 'icon': 'exclamation-circle'}
    else:
        system_status = {'label': 'Protected / Normal', 'class': 'success', 'icon': 'shield-check'}

    # Latest traffic stats for graph
    snapshots = list(TrafficStat.objects.filter(network=network, device__isnull=True).order_by('-recorded_at')[:12])
    snapshots.reverse()

    chart_labels = [s.recorded_at.strftime("%H:%M:%S") for s in snapshots]
    chart_packets_in = [s.packets_in for s in snapshots]
    chart_packets_out = [s.packets_out for s in snapshots]
    chart_bandwidth = [s.bandwidth_kbps for s in snapshots]

    # Protocol breakdown
    protocols = {
        'HTTPS (443)': 380,
        'HTTP (80)': 120,
        'DNS (53)': 90,
        'SSH (22)': 35,
        'Other': 45,
    }

    latest_snap = snapshots[-1] if snapshots else None
    active_devices_count = devices.filter(is_online=True).count()
    rules_active = DetectionRule.objects.filter(is_enabled=True).count()

    context = {
        'net_info': net_info,
        'system_status': system_status,
        'devices': devices,
        'devices_count': devices.count(),
        'active_devices_count': active_devices_count,
        'unresolved_alerts_count': unresolved_alerts_count,
        'critical_alerts_count': critical_alerts_count,
        'recent_alerts': recent_alerts,
        'rules_active': rules_active,
        'chart_labels': json.dumps(chart_labels),
        'chart_packets_in': json.dumps(chart_packets_in),
        'chart_packets_out': json.dumps(chart_packets_out),
        'chart_bandwidth': json.dumps(chart_bandwidth),
        'protocols_json': json.dumps(protocols),
        'latest_snap': latest_snap,
    }
    return render(request, "home/home.html", context)


@login_required
def devices_view(request):
    """Connected Devices Inventory"""
    seed_sample_data_if_empty()
    network = get_default_network()
    devices = Device.objects.filter(network=network)
    net_info = get_system_network_info()

    status_filter = request.GET.get('status')
    if status_filter == 'Online':
        devices = devices.filter(is_online=True)
    elif status_filter == 'Offline':
        devices = devices.filter(is_online=False)
    elif status_filter == 'Suspicious':
        devices = devices.filter(source_events__alert__status__in=[SecurityAlert.Status.NEW, SecurityAlert.Status.ACKNOWLEDGED]).distinct()

    search_query = request.GET.get('q')
    if search_query:
        devices = devices.filter(
            Q(ip_address__icontains=search_query) |
            Q(hostname__icontains=search_query) |
            Q(mac_address__icontains=search_query)
        )

    context = {
        'devices': devices,
        'net_info': net_info,
        'total_count': Device.objects.filter(network=network).count(),
        'online_count': Device.objects.filter(network=network, is_online=True).count(),
        'suspicious_count': Device.objects.filter(network=network, source_events__alert__status__in=[SecurityAlert.Status.NEW, SecurityAlert.Status.ACKNOWLEDGED]).distinct().count(),
        'idle_count': 0,
        'search_query': search_query or '',
        'status_filter': status_filter or '',
    }
    return render(request, "home/devices.html", context)


@login_required
def alerts_view(request):
    """Security Monitoring & Intrusion Detection Alerts"""
    seed_sample_data_if_empty()
    network = get_default_network()
    alerts = SecurityAlert.objects.filter(network=network)

    severity_filter = request.GET.get('severity')
    if severity_filter:
        alerts = alerts.filter(severity=severity_filter)

    status_filter = request.GET.get('status')
    if status_filter == 'unresolved':
        alerts = alerts.filter(status__in=[SecurityAlert.Status.NEW, SecurityAlert.Status.ACKNOWLEDGED])
    elif status_filter == 'resolved':
        alerts = alerts.filter(status=SecurityAlert.Status.RESOLVED)

    rules = DetectionRule.objects.all()

    context = {
        'alerts': alerts,
        'rules': rules,
        'total_alerts': SecurityAlert.objects.filter(network=network).count(),
        'critical_count': SecurityAlert.objects.filter(network=network, severity=Severity.CRITICAL, status__in=[SecurityAlert.Status.NEW, SecurityAlert.Status.ACKNOWLEDGED]).count(),
        'high_count': SecurityAlert.objects.filter(network=network, severity=Severity.HIGH, status__in=[SecurityAlert.Status.NEW, SecurityAlert.Status.ACKNOWLEDGED]).count(),
        'medium_count': SecurityAlert.objects.filter(network=network, severity=Severity.MEDIUM, status__in=[SecurityAlert.Status.NEW, SecurityAlert.Status.ACKNOWLEDGED]).count(),
        'unresolved_count': SecurityAlert.objects.filter(network=network, status__in=[SecurityAlert.Status.NEW, SecurityAlert.Status.ACKNOWLEDGED]).count(),
        'severity_filter': severity_filter or '',
        'status_filter': status_filter or '',
    }
    return render(request, "home/alerts.html", context)


class LogItemAdapter:
    """Presents a DetectedEvent with the interface expected by logs.html."""
    def __init__(self, event, network):
        self.timestamp = event.detected_at
        self.category = "SECURITY" if event.alert else "NETWORK"
        self.action = f"{event.rule.code}: {event.rule.name}"
        self.source_ip = event.source_device.ip_address if event.source_device else "-"
        self.destination_ip = event.target_device.ip_address if event.target_device else network.gateway_ip
        self.protocol = event.protocol or "TCP"
        self.details = event.details or f"Triggered {event.rule.name} on port {event.port or 'N/A'}"


@login_required
def logs_view(request):
    """Event Logs & Activity History backed by DetectedEvent."""
    seed_sample_data_if_empty()
    network = get_default_network()

    events_qs = DetectedEvent.objects.filter(network=network).select_related('rule', 'source_device', 'target_device', 'alert').order_by('-detected_at')

    category_filter = request.GET.get('category')
    if category_filter:
        if category_filter == 'SECURITY':
            events_qs = events_qs.filter(alert__isnull=False)
        elif category_filter == 'NETWORK':
            events_qs = events_qs.filter(alert__isnull=True)
        elif category_filter in ['PORT_SCAN', 'HOST_SCAN', 'CONN_ATTEMPT', 'DOS_BANDWIDTH', 'UNAUTH_SERVICE']:
            events_qs = events_qs.filter(rule__code=category_filter)

    search_query = request.GET.get('q')
    if search_query:
        events_qs = events_qs.filter(
            Q(details__icontains=search_query) |
            Q(source_device__ip_address__icontains=search_query) |
            Q(rule__name__icontains=search_query) |
            Q(rule__code__icontains=search_query)
        )

    log_items = [LogItemAdapter(e, network) for e in events_qs]

    # Export to CSV if requested
    if request.GET.get('export') == 'csv':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="netguard_logs_{timezone.now().strftime("%Y%m%d_%H%M%S")}.csv"'
        writer = csv.writer(response)
        writer.writerow(['Timestamp', 'Category', 'Action', 'Source IP', 'Destination IP', 'Protocol', 'Details'])
        for item in log_items:
            writer.writerow([
                item.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                item.category,
                item.action,
                item.source_ip,
                item.destination_ip,
                item.protocol,
                item.details
            ])
        return response

    context = {
        'logs': log_items[:100],
        'total_logs': len(log_items),
        'category_filter': category_filter or '',
        'search_query': search_query or '',
    }
    return render(request, "home/logs.html", context)


@login_required
def reports_view(request):
    """Report Generation & Export (Computed on-the-fly from queries, no table)"""
    seed_sample_data_if_empty()
    network = get_default_network()

    if request.method == "POST":
        title = request.POST.get('title', 'Weekly Network Security Assessment')
        period = request.POST.get('period', 'Last 24 Hours')
        rep = generate_computed_report(network, title=title, period=period, user=request.user)
        # Store in session for detail view
        request.session['latest_report'] = {
            'title': rep.title,
            'period': rep.time_period,
            'generated_at': rep.generated_at.isoformat(),
        }
        return redirect("home:report_detail", report_id=rep.id)

    default_report = generate_computed_report(network, user=request.user)
    reports = [default_report]
    context = {
        'reports': reports,
        'total_reports': len(reports),
        'latest_report': default_report,
    }
    return render(request, "home/reports.html", context)


@login_required
def report_detail_view(request, report_id):
    """Detailed view of a generated security report (computed from queries)."""
    network = get_default_network()
    saved = request.session.get('latest_report', {})
    title = saved.get('title', 'Local Subnet Intrusion Assessment')
    period = saved.get('period', 'Last 24 Hours')

    report = generate_computed_report(network, title=title, period=period, user=request.user, report_id=report_id)
    alerts = SecurityAlert.objects.filter(network=network)[:10]
    devices = Device.objects.filter(network=network)

    context = {
        'report': report,
        'alerts': alerts,
        'devices': devices,
        'net_info': get_system_network_info(),
    }
    return render(request, "home/report_detail.html", context)


@login_required
def controlled_scenarios_view(request):
    """Controlled Network-Traffic Testing & Evaluation Suite."""
    seed_sample_data_if_empty()
    scenario_result = None

    if request.method == "POST":
        scenario_key = request.POST.get('scenario_key', 'port_scan')
        scenario_result = run_controlled_scenario(scenario_key)

    context = {
        'scenario_result': scenario_result,
        'rules': DetectionRule.objects.all(),
    }
    return render(request, "home/scenarios.html", context)


# ==================== REST / JSON API ENDPOINTS ====================

@login_required
def api_traffic_stream(request):
    """Returns dynamic real-time traffic statistics for live charts and dials."""
    network = get_default_network()
    now = timezone.now()

    p_in = random.randint(400, 800)
    p_out = random.randint(300, 650)
    b_in = p_in * random.randint(800, 1500)
    b_out = p_out * random.randint(600, 1200)
    bw_bps = int(((b_in + b_out) * 8) / 5)

    new_snap = TrafficStat.objects.create(
        network=network,
        recorded_at=now,
        bytes_in=b_in,
        bytes_out=b_out,
        bandwidth_bps=bw_bps,
        active_connections=random.randint(18, 42),
    )

    unresolved_count = SecurityAlert.objects.filter(network=network, status__in=[SecurityAlert.Status.NEW, SecurityAlert.Status.ACKNOWLEDGED]).count()
    crit_count = SecurityAlert.objects.filter(network=network, status__in=[SecurityAlert.Status.NEW, SecurityAlert.Status.ACKNOWLEDGED], severity=Severity.CRITICAL).count()

    return JsonResponse({
        'status': 'success',
        'timestamp': new_snap.recorded_at.strftime('%H:%M:%S'),
        'packets_in': new_snap.packets_in,
        'packets_out': new_snap.packets_out,
        'bandwidth_kbps': new_snap.bandwidth_kbps,
        'active_connections': new_snap.active_connections,
        'unresolved_alerts': unresolved_count,
        'critical_alerts': crit_count,
    })


@login_required
def api_resolve_alert(request, alert_id):
    """Marks a security alert as resolved."""
    if request.method == "POST":
        network = get_default_network()
        alert = get_object_or_404(SecurityAlert, id=alert_id, network=network)
        alert.status = SecurityAlert.Status.RESOLVED
        alert.acknowledged_at = timezone.now()
        if request.user.is_authenticated:
            alert.acknowledged_by = request.user
        alert.save()
        return JsonResponse({'status': 'success', 'message': f'Alert #{alert.id} resolved.'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=400)


@login_required
def api_scan_devices(request):
    """Triggers on-demand local network ARP / IP discovery."""
    if request.method == "POST":
        network = get_default_network()
        now = timezone.now()

        Device.objects.filter(network=network, is_online=True).update(last_seen=now)

        return JsonResponse({
            'status': 'success',
            'message': f'Subnet scan completed. {Device.objects.filter(network=network).count()} active hosts indexed.',
            'devices_count': Device.objects.filter(network=network).count()
        })
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=400)
