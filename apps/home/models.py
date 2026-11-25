from django.conf import settings
from django.db import models

from apps.networks.models import Network


class SecurityReport(models.Model):
    network = models.ForeignKey(
        Network,
        on_delete=models.CASCADE,
        related_name="security_reports",
    )
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="security_reports",
    )
    title = models.CharField(max_length=150)
    time_period = models.CharField(max_length=50)
    executive_summary = models.TextField()
    findings = models.TextField()
    recommendations = models.TextField()
    total_events = models.PositiveIntegerField(default=0)
    critical_count = models.PositiveIntegerField(default=0)
    high_count = models.PositiveIntegerField(default=0)
    medium_count = models.PositiveIntegerField(default=0)
    low_count = models.PositiveIntegerField(default=0)
    monitored_devices = models.PositiveIntegerField(default=0)
    network_health_score = models.PositiveIntegerField(default=95)
    generated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-generated_at"]
