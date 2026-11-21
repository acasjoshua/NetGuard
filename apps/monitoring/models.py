"""
monitoring app  (ERD group: orange)

Tables
    monitoring_device       -> Device       (connected devices)
    monitoring_trafficstat  -> TrafficStat  (traffic statistics samples)
"""
from django.db import models

from apps.networks.models import Network


class Device(models.Model):
    network = models.ForeignKey(
        Network,
        on_delete=models.CASCADE,
        related_name="devices",
    )
    ip_address = models.GenericIPAddressField()                 # PostgreSQL: inet
    mac_address = models.CharField(max_length=17)               # AA:BB:CC:DD:EE:FF
    hostname = models.CharField(max_length=100, null=True, blank=True)
    is_online = models.BooleanField(default=True)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["network", "mac_address"],
                name="unique_network_mac_address",
            ),
        ]
        ordering = ["network", "ip_address"]

    @property
    def status(self):
        if self.source_events.filter(alert__status__in=['NEW', 'ACKNOWLEDGED']).exists():
            return "Suspicious"
        return "Online" if self.is_online else "Offline"

    @property
    def vendor(self):
        return "Local Network Device"

    @property
    def os_info(self):
        return "Network OS"

    @property
    def device_type(self):
        if self.hostname and "gateway" in self.hostname.lower():
            return "Gateway"
        if self.hostname and "server" in self.hostname.lower():
            return "Server"
        if self.hostname and "printer" in self.hostname.lower():
            return "IoT"
        if self.hostname and "macbook" in self.hostname.lower():
            return "Laptop"
        return "Workstation"

    @property
    def open_ports(self):
        services = self.network.allowed_services.all()
        return ", ".join(str(s.port) for s in services) if services.exists() else "80, 443"

    @property
    def packet_count(self):
        stat = self.traffic_stats.first()
        return stat.bandwidth_bps if stat else 0

    def __str__(self):
        return f"{self.ip_address} ({self.mac_address})"


class TrafficStat(models.Model):
    network = models.ForeignKey(
        Network,
        on_delete=models.CASCADE,
        related_name="traffic_stats",
    )
    # NULL = network-wide sample, set = per-device sample (used by the bandwidth/DoS rule)
    device = models.ForeignKey(
        Device,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="traffic_stats",
    )
    recorded_at = models.DateTimeField()
    bytes_in = models.PositiveBigIntegerField(default=0)
    bytes_out = models.PositiveBigIntegerField(default=0)
    bandwidth_bps = models.PositiveBigIntegerField(default=0)
    active_connections = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["-recorded_at"]

    @property
    def timestamp(self):
        return self.recorded_at

    @property
    def bandwidth_kbps(self):
        return round(self.bandwidth_bps / 1000, 2)

    @property
    def packets_in(self):
        return max(1, int(self.bytes_in / 1000))

    @property
    def packets_out(self):
        return max(1, int(self.bytes_out / 1000))

    def __str__(self):
        return f"{self.network.name} @ {self.recorded_at:%Y-%m-%d %H:%M:%S}"
