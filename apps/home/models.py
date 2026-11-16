from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class Device(models.Model):
    DEVICE_ROLES = [
        ('Gateway', 'Gateway / Router'),
        ('Workstation', 'Workstation / Desktop'),
        ('Laptop', 'Laptop / Portable'),
        ('Server', 'Local Server / NAS'),
        ('Mobile', 'Mobile / Tablet'),
        ('IoT', 'IoT / Smart Device'),
        ('Suspicious', 'Unidentified / Scanner'),
    ]

    STATUS_CHOICES = [
        ('Online', 'Online'),
        ('Idle', 'Idle'),
        ('Suspicious', 'Suspicious / Flagged'),
        ('Offline', 'Offline'),
    ]

    ip_address = models.CharField(max_length=45, unique=True)
    mac_address = models.CharField(max_length=20, blank=True)
    hostname = models.CharField(max_length=120, blank=True)
    vendor = models.CharField(max_length=120, blank=True)
    device_type = models.CharField(max_length=50, choices=DEVICE_ROLES, default='Workstation')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Online')
    open_ports = models.TextField(blank=True, default='80, 443')
    os_info = models.CharField(max_length=100, blank=True, default='Unknown OS')
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    packet_count = models.BigIntegerField(default=0)
    byte_count = models.BigIntegerField(default=0)

    class Meta:
        ordering = ['ip_address']

    def __str__(self):
        return f"{self.hostname or self.ip_address} ({self.ip_address})"


class SecurityAlert(models.Model):
    SEVERITY_CHOICES = [
        ('CRITICAL', 'Critical'),
        ('HIGH', 'High'),
        ('MEDIUM', 'Medium'),
        ('LOW', 'Low'),
    ]

    EVENT_TYPE_CHOICES = [
        ('PORT_SCAN', 'Port Scanning Attempt'),
        ('CONNECTION_BURST', 'Excessive Connection Rate'),
        ('ABNORMAL_TRAFFIC', 'Abnormal Traffic Rate'),
        ('SUSPICIOUS_PORT', 'Suspicious Port Access'),
        ('UNAUTHORIZED_DEVICE', 'Unauthorized Device Access'),
    ]

    title = models.CharField(max_length=150)
    event_type = models.CharField(max_length=50, choices=EVENT_TYPE_CHOICES)
    rule_triggered = models.CharField(max_length=120)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='MEDIUM')
    source_ip = models.CharField(max_length=45)
    destination_ip = models.CharField(max_length=45, default='192.168.1.1')
    description = models.TextField()
    details = models.TextField(blank=True)
    packet_rate = models.FloatField(default=0.0)
    port_count = models.IntegerField(default=0)
    timestamp = models.DateTimeField(default=timezone.now)
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.CharField(max_length=100, blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.severity}] {self.title} - {self.source_ip}"


class TrafficSnapshot(models.Model):
    timestamp = models.DateTimeField(default=timezone.now)
    bytes_in = models.BigIntegerField(default=0)
    bytes_out = models.BigIntegerField(default=0)
    packets_in = models.IntegerField(default=0)
    packets_out = models.IntegerField(default=0)
    active_connections = models.IntegerField(default=0)
    bandwidth_kbps = models.FloatField(default=0.0)
    tcp_count = models.IntegerField(default=0)
    udp_count = models.IntegerField(default=0)
    icmp_count = models.IntegerField(default=0)
    http_count = models.IntegerField(default=0)
    https_count = models.IntegerField(default=0)
    dns_count = models.IntegerField(default=0)
    ssh_count = models.IntegerField(default=0)
    other_count = models.IntegerField(default=0)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"TrafficSnapshot @ {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"


class ActivityLog(models.Model):
    CATEGORY_CHOICES = [
        ('SECURITY', 'Security Alert'),
        ('NETWORK', 'Network Event'),
        ('SYSTEM', 'System Activity'),
        ('AUTH', 'Authentication'),
    ]

    timestamp = models.DateTimeField(default=timezone.now)
    action = models.CharField(max_length=120)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='NETWORK')
    source_ip = models.CharField(max_length=45, blank=True)
    destination_ip = models.CharField(max_length=45, blank=True)
    protocol = models.CharField(max_length=20, default='TCP')
    details = models.TextField()
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.timestamp.strftime('%H:%M:%S')} [{self.category}] {self.action}"


class DetectionRule(models.Model):
    code = models.CharField(max_length=30, unique=True)
    name = models.CharField(max_length=120)
    description = models.TextField()
    rule_type = models.CharField(max_length=50)
    threshold_value = models.FloatField(default=10.0)
    time_window_seconds = models.IntegerField(default=15)
    severity = models.CharField(max_length=20, default='HIGH')
    is_enabled = models.BooleanField(default=True)
    times_triggered = models.IntegerField(default=0)

    class Meta:
        ordering = ['code']

    def __str__(self):
        return f"{self.code}: {self.name}"


class SecurityReport(models.Model):
    title = models.CharField(max_length=150)
    report_type = models.CharField(max_length=50, default='Comprehensive Network Audit')
    generated_at = models.DateTimeField(default=timezone.now)
    generated_by = models.ForeignKey(User, on_delete=models.CASCADE)
    time_period = models.CharField(max_length=50, default='Last 24 Hours')
    total_events = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    monitored_devices = models.IntegerField(default=0)
    network_health_score = models.IntegerField(default=95)
    executive_summary = models.TextField()
    findings = models.TextField()
    recommendations = models.TextField()

    class Meta:
        ordering = ['-generated_at']

    def __str__(self):
        return f"{self.title} ({self.generated_at.strftime('%Y-%m-%d')})"
