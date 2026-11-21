from django.contrib import admin

from .models import Device, TrafficStat


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "mac_address", "hostname", "network", "is_online", "last_seen")
    list_filter = ("is_online", "network")
    search_fields = ("ip_address", "mac_address", "hostname")


@admin.register(TrafficStat)
class TrafficStatAdmin(admin.ModelAdmin):
    list_display = ("network", "device", "recorded_at", "bytes_in", "bytes_out", "bandwidth_bps", "active_connections")
    list_filter = ("network",)
