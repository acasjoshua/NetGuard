from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("home", "0002_remove_legacy_monitoring_models"),
        ("networks", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="SecurityReport",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("title", models.CharField(max_length=150)),
                ("time_period", models.CharField(max_length=50)),
                ("executive_summary", models.TextField()),
                ("findings", models.TextField()),
                ("recommendations", models.TextField()),
                ("total_events", models.PositiveIntegerField(default=0)),
                ("critical_count", models.PositiveIntegerField(default=0)),
                ("high_count", models.PositiveIntegerField(default=0)),
                ("medium_count", models.PositiveIntegerField(default=0)),
                ("low_count", models.PositiveIntegerField(default=0)),
                ("monitored_devices", models.PositiveIntegerField(default=0)),
                ("network_health_score", models.PositiveIntegerField(default=95)),
                ("generated_at", models.DateTimeField(auto_now_add=True)),
                ("generated_by", models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="security_reports", to=settings.AUTH_USER_MODEL)),
                ("network", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="security_reports", to="networks.network")),
            ],
            options={"ordering": ["-generated_at"]},
        ),
    ]
