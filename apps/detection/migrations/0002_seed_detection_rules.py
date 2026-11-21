"""
Reference data from the ERD: the 5 planned rows of detection_detectionrule.

Thresholds and time windows are starting values to be tuned during testing.
Units of `threshold` per rule:
    PORT_SCAN       distinct ports probed by one device
    HOST_SCAN       distinct hosts probed on the same port by one device
    CONN_ATTEMPT    failed connection attempts from one device
    DOS_BANDWIDTH   bits per second from one device
    UNAUTH_SERVICE  services found on ports missing from networks_allowedservice
"""
from django.db import migrations

RULES = [
    {
        "code": "PORT_SCAN",
        "name": "Port scanning",
        "description": "One device attempts to connect to many different ports.",
        "threshold": 15,
        "time_window_sec": 60,
        "default_severity": "MEDIUM",
    },
    {
        "code": "HOST_SCAN",
        "name": "Host scanning",
        "description": "One device attempts to connect to the same port across many hosts.",
        "threshold": 10,
        "time_window_sec": 60,
        "default_severity": "MEDIUM",
    },
    {
        "code": "CONN_ATTEMPT",
        "name": "Connection attempts",
        "description": "Repeated failed connection attempts from one device.",
        "threshold": 20,
        "time_window_sec": 60,
        "default_severity": "LOW",
    },
    {
        "code": "DOS_BANDWIDTH",
        "name": "Denial of service (bandwidth)",
        "description": "A device's bandwidth usage exceeds the allowed limit (bits per second).",
        "threshold": 50_000_000,
        "time_window_sec": 10,
        "default_severity": "HIGH",
    },
    {
        "code": "UNAUTH_SERVICE",
        "name": "Unauthorized network service",
        "description": "A service is running on a port that is not in the network's allowed services.",
        "threshold": 1,
        "time_window_sec": 60,
        "default_severity": "HIGH",
    },
]


def seed_rules(apps, schema_editor):
    DetectionRule = apps.get_model("detection", "DetectionRule")
    for rule in RULES:
        DetectionRule.objects.update_or_create(
            code=rule["code"],
            defaults={**rule, "is_enabled": True},
        )


def unseed_rules(apps, schema_editor):
    DetectionRule = apps.get_model("detection", "DetectionRule")
    DetectionRule.objects.filter(code__in=[r["code"] for r in RULES]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("detection", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(seed_rules, unseed_rules),
    ]
