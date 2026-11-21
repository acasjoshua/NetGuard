from django.contrib import admin

from .models import DetectedEvent, DetectionRule, SecurityAlert


@admin.register(DetectionRule)
class DetectionRuleAdmin(admin.ModelAdmin):
    list_display = ("code", "name", "threshold", "time_window_sec", "default_severity", "is_enabled")
    list_filter = ("is_enabled", "default_severity")


@admin.register(SecurityAlert)
class SecurityAlertAdmin(admin.ModelAdmin):
    list_display = ("title", "network", "severity", "status", "created_at", "acknowledged_by")
    list_filter = ("severity", "status", "network")


@admin.register(DetectedEvent)
class DetectedEventAdmin(admin.ModelAdmin):
    list_display = ("rule", "network", "source_device", "target_device", "port", "protocol", "event_count", "detected_at")
    list_filter = ("rule", "network", "protocol")
