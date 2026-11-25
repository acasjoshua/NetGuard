import csv
import json
import random
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone
from django.core.paginator import Paginator
from datetime import timedelta
from django.db.models import Q, Subquery

from apps.monitoring.models import Device, TrafficStat
from apps.detection.models import DetectionRule, SecurityAlert, DetectedEvent, Severity
from apps.user_settings.models import UserSettings
from apps.networks.models import Network, UserNetwork
from apps.home.models import SecurityReport
from .ids_engine import (
    seed_sample_data_if_empty,
    get_system_network_info,
    get_default_network,
    is_in_network_subnet,
    run_controlled_scenario,
    collect_live_network_snapshot,
    collect_live_traffic_sample,
)

def _local_devices(network):
    return [
        device
        for device in Device.objects.filter(network=network)
        if is_in_network_subnet(network, device.ip_address)
    ]

def _get_user_network(request):
    """Resolve one network that the authenticated user is authorized to access."""
    network_id = request.GET.get('network') or request.session.get('active_network_id')
    link = None
    if network_id:
        link = request.user.network_links.select_related('network').filter(
            network_id=network_id
        ).first()

    if link is None:
        link = request.user.network_links.select_related('network').order_by(
            '-role', 'network__name'
        ).first()

    if link is None:
        network = get_default_network()
        link = UserNetwork.objects.create(
            user=request.user,
            network=network,
            role=UserNetwork.Role.OWNER,
        )

    request.session['active_network_id'] = link.network_id
    return link.network

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
    dev_count = len(_local_devices(network))

    health = max(45, 100 - (crit * 15 + high * 8 + med * 3))

    exec_summary = (
        f"This report summarizes sample records and generated rule-evaluation events "
        f"for {period}; it is not based on live network collection. "
        f"A total of {total_ev} sample events are stored. "
        f"{crit} critical and {high} high-severity sample alerts are recorded. "
        f"Sample-data indicator score: {health}%."
    )
    findings = (
        f"1. Rule evaluation: Generated events are checked against configured detection rules.\n"
        f"2. Traffic rates and device activity are illustrative sample data, not measurements.\n"
        f"3. Vendor, OS, and open-port details are not collected.\n"
        f"4. {dev_count} sample inventory records are assigned to {network.subnet_cidr}."
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
    network = _get_user_network(request)
    net_info = get_system_network_info()
    user_settings, _ = UserSettings.objects.get_or_create(user=request.user)

    devices = _local_devices(network)
    alerts = SecurityAlert.objects.filter(network=network)
    recent_alerts = alerts[:5]
    unresolved_alerts_count = alerts.filter(status__in=[SecurityAlert.Status.NEW, SecurityAlert.Status.ACKNOWLEDGED]).count()
    critical_alerts_count = alerts.filter(status__in=[SecurityAlert.Status.NEW, SecurityAlert.Status.ACKNOWLEDGED], severity=Severity.CRITICAL).count()

    # Determine overall security status
    if critical_alerts_count > 0:
        system_status = {'label': 'Sample Critical Alerts', 'class': 'danger', 'icon': 'exclamation-triangle'}
    elif unresolved_alerts_count > 0:
        system_status = {'label': 'Sample Alerts Present', 'class': 'warning', 'icon': 'exclamation-circle'}
    else:
        system_status = {'label': 'Demo Mode - No Live Monitoring', 'class': 'warning', 'icon': 'circle-info'}

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
    idle_cutoff = timezone.now() - timedelta(minutes=5)
    active_devices_count = sum(
        1 for device in devices
        if device.is_online and device.last_seen >= idle_cutoff
    )
    rules_active = DetectionRule.objects.filter(is_enabled=True).count()
    alert_cursor = (
        alerts.order_by('-id').values_list('id', flat=True).first() or 0
    )

    context = {
        'net_info': net_info,
        'system_status': system_status,
        'live_collection': network.connection_status == network.ConnectionStatus.CONNECTED,
        'devices': devices,
        'devices_count': len(devices),
        'active_devices_count': active_devices_count,
        'unresolved_alerts_count': unresolved_alerts_count,
        'critical_alerts_count': critical_alerts_count,
        'recent_alerts': recent_alerts,
        'rules_active': rules_active,
        'settings': user_settings,
        'alert_cursor': alert_cursor,
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
    network = _get_user_network(request)
    all_devices = _local_devices(network)
    devices = all_devices
    net_info = get_system_network_info()

    status_filter = request.GET.get('status')
    idle_cutoff = timezone.now() - timedelta(minutes=5)

    open_alert_sources = DetectedEvent.objects.filter(
        network=network,
        alert__status__in=['NEW', 'ACKNOWLEDGED'],
    ).values('source_device_id').order_by()
    suspicious_qs = Device.objects.filter(
        network=network,
        id__in=Subquery(open_alert_sources),
    ).order_by('ip_address')
    suspicious_ids = set(suspicious_qs.values_list('id', flat=True))

    if status_filter == 'Online':
        devices = [
            device for device in devices
            if device.is_online and device.last_seen >= idle_cutoff
        ]
    elif status_filter == 'Offline':
        devices = [device for device in devices if not device.is_online]
    elif status_filter == 'Idle':
        devices = [
            device for device in devices
            if device.is_online and device.last_seen < idle_cutoff
        ]
    elif status_filter == 'Suspicious':
        devices = [device for device in devices if device.id in suspicious_ids]

    search_query = request.GET.get('q')
    if search_query:
        query = search_query.casefold()
        devices = [
            device for device in devices
            if query in device.ip_address.casefold()
            or query in (device.hostname or '').casefold()
            or query in device.mac_address.casefold()
        ]

    context = {
        'devices': devices,
        'net_info': net_info,
        'total_count': len(all_devices),
        'online_count': sum(
            1 for device in all_devices
            if device.is_online and device.last_seen >= idle_cutoff
        ),
        'suspicious_count': sum(
            1 for device in all_devices if device.id in suspicious_ids
        ),
        'idle_count': sum(
            1 for device in all_devices
            if device.is_online and device.last_seen < idle_cutoff
        ),
        'search_query': search_query or '',
        'status_filter': status_filter or '',
    }
    return render(request, "home/devices.html", context)


@login_required
def alerts_view(request):
    """Security Monitoring & Intrusion Detection Alerts"""
    seed_sample_data_if_empty()
    network = _get_user_network(request)
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

    paginator = Paginator(alerts, 25)
    page_obj = paginator.get_page(request.GET.get("page"))

    context = {
        'alerts': page_obj.object_list,
        'page_obj': page_obj,
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
    network = _get_user_network(request)

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

    paginator = Paginator(log_items, 50)
    page_obj = paginator.get_page(request.GET.get("page"))

    context = {
        'logs': page_obj.object_list,
        'page_obj': page_obj,
        'total_logs': len(log_items),
        'category_filter': category_filter or '',
        'search_query': search_query or '',
    }
    return render(request, "home/logs.html", context)


@login_required
def reports_view(request):
    """Report Generation & Export (Computed on-the-fly from queries, no table)"""
    seed_sample_data_if_empty()
    network = _get_user_network(request)

    if request.method == "POST":
        title = request.POST.get('title', 'Weekly Network Security Assessment')
        period = request.POST.get('period', 'Last 24 Hours')
        rep = generate_computed_report(network, title=title, period=period, user=request.user)
        stored = SecurityReport.objects.create(
            network=network,
            generated_by=request.user,
            title=rep.title,
            time_period=rep.time_period,
            executive_summary=rep.executive_summary,
            findings=rep.findings,
            recommendations=rep.recommendations,
            total_events=rep.total_events,
            critical_count=rep.critical_count,
            high_count=rep.high_count,
            medium_count=rep.medium_count,
            low_count=rep.low_count,
            monitored_devices=rep.monitored_devices,
            network_health_score=rep.network_health_score,
        )
        request.session['latest_report'] = {
            'title': stored.title,
            'period': stored.time_period,
            'generated_at': stored.generated_at.isoformat(),
        }
        return redirect("home:report_detail", report_id=stored.id)

    default_report = generate_computed_report(network, user=request.user)
    reports = list(SecurityReport.objects.filter(network=network)[:20])
    if not reports:
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
    network = _get_user_network(request)
    stored = SecurityReport.objects.filter(
        id=report_id,
        network=network,
    ).first()
    if stored:
        report = ComputedReport(
            id_val=stored.id,
            title=stored.title,
            time_period=stored.time_period,
            generated_by=stored.generated_by or request.user,
            total_events=stored.total_events,
            critical_count=stored.critical_count,
            high_count=stored.high_count,
            medium_count=stored.medium_count,
            low_count=stored.low_count,
            monitored_devices=stored.monitored_devices,
            network_health_score=stored.network_health_score,
            executive_summary=stored.executive_summary,
            findings=stored.findings,
            recommendations=stored.recommendations,
            generated_at=stored.generated_at,
        )
    else:
        saved = request.session.get('latest_report', {})
        title = saved.get('title', 'Local Subnet Intrusion Assessment')
        period = saved.get('period', 'Last 24 Hours')
        report = generate_computed_report(
            network,
            title=title,
            period=period,
            user=request.user,
            report_id=report_id,
        )
    alerts = SecurityAlert.objects.filter(network=network)[:10]
    devices = _local_devices(network)

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
    """Return live interface telemetry when available and new alert notifications."""
    network = _get_user_network(request)
    now = timezone.now()
    try:
        after_id = int(request.GET.get('after_id', 0))
    except ValueError:
        return JsonResponse(
            {'status': 'error', 'message': 'after_id must be an integer.'},
            status=400,
        )

    new_snap = collect_live_traffic_sample(network)
    data_source = "live" if new_snap is not None else "unavailable"
    if new_snap is None:
        new_snap = TrafficStat.objects.filter(
            network=network,
            device__isnull=True,
        ).order_by("-recorded_at").first()
        if new_snap is None:
            new_snap = TrafficStat.objects.create(
                network=network,
                recorded_at=now,
                bandwidth_bps=0,
            )

    user_settings, _ = UserSettings.objects.get_or_create(user=request.user)
    new_alerts = SecurityAlert.objects.filter(
        network=network, id__gt=after_id
    ).order_by('id')[:50]
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
        'data_source': data_source,
        'new_alerts': [
            {
                'id': alert.id,
                'title': alert.title,
                'message': alert.message,
                'severity': alert.severity,
            }
            for alert in new_alerts
        ],
        'sound_alerts': user_settings.sound_alerts,
        'desktop_alerts': user_settings.desktop_alerts,
    })


@login_required
def api_resolve_alert(request, alert_id):
    """Marks a security alert as resolved."""
    if request.method == "POST":
        network = _get_user_network(request)
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
    """Discover local devices and telemetry using the host network interfaces."""
    if request.method != "POST":
        return JsonResponse(
            {'status': 'error', 'message': 'Invalid request method.'},
            status=400,
        )
    network = _get_user_network(request)
    try:
        snapshot = collect_live_network_snapshot(network)
        network.connection_status = (
            Network.ConnectionStatus.CONNECTED
            if snapshot['live']
            else Network.ConnectionStatus.ERROR
        )
        network.last_scanned_at = timezone.now()
        network.save(update_fields=['connection_status', 'last_scanned_at'])
        return JsonResponse({
            'status': 'success' if snapshot['live'] else 'partial',
            'message': snapshot['message'],
            'devices_discovered': snapshot['devices_discovered'],
            'data_source': 'live' if snapshot['live'] else 'unavailable',
        })
    except Exception as exc:
        network.connection_status = Network.ConnectionStatus.ERROR
        network.save(update_fields=['connection_status'])
        return JsonResponse({
            'status': 'error',
            'message': f'Live collection failed: {exc}',
            'data_source': 'unavailable',
        }, status=503)
