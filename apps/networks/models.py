"""
networks app  (ERD group: blue)

Tables
    networks_network         -> Network
    networks_usernetwork     -> UserNetwork      (junction: users <-> networks)
    networks_allowedservice  -> AllowedService   (baseline for the unauthorized-service rule)
"""
from django.conf import settings
from django.db import models


class Protocol(models.TextChoices):
    """Shared by networks_allowedservice and detection_detectedevent."""
    TCP = "TCP", "TCP"
    UDP = "UDP", "UDP"
    ICMP = "ICMP", "ICMP"


class Network(models.Model):
    class ConnectionStatus(models.TextChoices):
        CONNECTED = "CONNECTED", "Connected"
        DISCONNECTED = "DISCONNECTED", "Disconnected"
        ERROR = "ERROR", "Error"

    name = models.CharField(max_length=100)
    subnet_cidr = models.CharField(max_length=18)               # e.g. 192.168.1.0/24
    gateway_ip = models.GenericIPAddressField()                 # PostgreSQL: inet
    area = models.CharField(max_length=100)                     # groups networks on the Dashboard
    interface_name = models.CharField(max_length=50)
    connection_status = models.CharField(
        max_length=20,
        choices=ConnectionStatus.choices,
        default=ConnectionStatus.DISCONNECTED,
    )
    last_scanned_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # Many-to-many between users and networks, stored in networks_usernetwork.
    users = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        through="UserNetwork",
        related_name="networks",
    )

    class Meta:
        ordering = ["area", "name"]

    def __str__(self):
        return f"{self.name} ({self.subnet_cidr})"


class UserNetwork(models.Model):
    class Role(models.TextChoices):
        OWNER = "OWNER", "Owner"
        SAVED = "SAVED", "Saved"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="network_links",
    )
    network = models.ForeignKey(
        Network,
        on_delete=models.CASCADE,
        related_name="user_links",
    )
    role = models.CharField(max_length=10, choices=Role.choices, default=Role.SAVED)
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["user", "network"], name="unique_user_network"
            ),
        ]

    def __str__(self):
        return f"{self.user} - {self.network} ({self.role})"


class AllowedService(models.Model):
    network = models.ForeignKey(
        Network,
        on_delete=models.CASCADE,
        related_name="allowed_services",
    )
    port = models.PositiveIntegerField()
    protocol = models.CharField(max_length=10, choices=Protocol.choices, default=Protocol.TCP)
    service_name = models.CharField(max_length=50)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["network", "port", "protocol"],
                name="unique_network_port_protocol",
            ),
        ]
        ordering = ["network", "port"]

    def __str__(self):
        return f"{self.service_name} {self.port}/{self.protocol} on {self.network.name}"
