"""
detection app  (ERD group: red)

Tables
    detection_detectionrule  -> DetectionRule  (the 5 rule-based detections)
    detection_securityalert  -> SecurityAlert  (alerts raised from events)
    detection_detectedevent  -> DetectedEvent  (individual detected events)
"""
from django.conf import settings
from django.db import models

from apps.monitoring.models import Device
from apps.networks.models import Network, Protocol


class Severity(models.TextChoices):
    LOW = "LOW", "Low"
    MEDIUM = "MEDIUM", "Medium"
    HIGH = "HIGH", "High"
    CRITICAL = "CRITICAL", "Critical"


class DetectionRule(models.Model):
    class Code(models.TextChoices):
        PORT_SCAN = "PORT_SCAN", "Port scanning"
        HOST_SCAN = "HOST_SCAN", "Host scanning"
        CONN_ATTEMPT = "CONN_ATTEMPT", "Connection attempts"
        DOS_BANDWIDTH = "DOS_BANDWIDTH", "Denial of service (bandwidth)"
        UNAUTH_SERVICE = "UNAUTH_SERVICE", "Unauthorized network service"

    code = models.CharField(max_length=30, unique=True, choices=Code.choices)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    threshold = models.PositiveIntegerField()
    time_window_sec = models.PositiveIntegerField()
    default_severity = models.CharField(
        max_length=10, choices=Severity.choices, default=Severity.MEDIUM
    )
    is_enabled = models.BooleanField(default=True)

    class Meta:
        ordering = ["id"]

    @property
    def threshold_value(self):
        return float(self.threshold)

    @property
    def time_window_seconds(self):
        return self.time_window_sec

    @property
    def severity(self):
        return self.default_severity

    @property
    def times_triggered(self):
        return self.events.count()

    def __str__(self):
        return f"{self.code} - {self.name}"


class SecurityAlert(models.Model):
    class Status(models.TextChoices):
        NEW = "NEW", "New"
        ACKNOWLEDGED = "ACKNOWLEDGED", "Acknowledged"
        RESOLVED = "RESOLVED", "Resolved"

    network = models.ForeignKey(
        Network,
        on_delete=models.CASCADE,
        related_name="alerts",
    )
    # Who reviewed the alert. Informational only: the system is an IDS, not an IPS.
    acknowledged_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="acknowledged_alerts",
    )
    severity = models.CharField(max_length=10, choices=Severity.choices, default=Severity.MEDIUM)
    status = models.CharField(max_length=15, choices=Status.choices, default=Status.NEW)
    title = models.CharField(max_length=150)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    @property
    def is_resolved(self):
        return self.status == self.Status.RESOLVED

    @property
    def source_ip(self):
        ev = self.events.first()
        return ev.source_device.ip_address if ev else "-"

    @property
    def destination_ip(self):
        ev = self.events.first()
        if ev and ev.target_device:
            return ev.target_device.ip_address
        return "-"

    @property
    def rule_triggered(self):
        ev = self.events.first()
        if ev:
            return f"{ev.rule.code} ({ev.rule.name})"
        return ""

    @property
    def description(self):
        return self.message

    @property
    def details(self):
        ev = self.events.first()
        return ev.details if ev else ""

    @property
    def timestamp(self):
        return self.created_at

    @property
    def event_type(self):
        ev = self.events.first()
        return ev.rule.code if ev else ""

    def get_event_type_display(self):
        ev = self.events.first()
        return ev.rule.name if ev else self.title

    def __str__(self):
        return f"[{self.severity}] {self.title}"


class DetectedEvent(models.Model):
    # Denormalized on purpose (derivable via source_device) so events can be
    # queried per network without a join.
    network = models.ForeignKey(
        Network,
        on_delete=models.CASCADE,
        related_name="events",
    )
    rule = models.ForeignKey(
        DetectionRule,
        on_delete=models.PROTECT,
        related_name="events",
    )
    source_device = models.ForeignKey(
        Device,
        on_delete=models.CASCADE,
        related_name="source_events",
    )
    target_device = models.ForeignKey(
        Device,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="target_events",
    )
    alert = models.ForeignKey(
        SecurityAlert,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="events",
    )
    port = models.PositiveIntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10, choices=Protocol.choices, null=True, blank=True)
    event_count = models.PositiveIntegerField(default=1)
    details = models.TextField(blank=True)
    detected_at = models.DateTimeField()

    class Meta:
        ordering = ["-detected_at"]

    def __str__(self):
        return f"{self.rule.code} from {self.source_device} @ {self.detected_at:%Y-%m-%d %H:%M:%S}"
