from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("monitoring", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="device",
            name="vendor_name",
            field=models.CharField(default="Unknown", max_length=100),
        ),
        migrations.AddField(
            model_name="device",
            name="os_name",
            field=models.CharField(default="Not detected", max_length=100),
        ),
        migrations.AddField(
            model_name="device",
            name="device_type_name",
            field=models.CharField(default="Unknown", max_length=100),
        ),
        migrations.AddField(
            model_name="device",
            name="open_ports_text",
            field=models.CharField(default="Not scanned", max_length=255),
        ),
    ]
