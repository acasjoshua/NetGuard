from django.contrib.auth.models import User
from django.db import models

class UserSettings(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='settings')
    dark_mode = models.BooleanField(default=True)
    email_notifications = models.BooleanField(default=True)
    sound_alerts = models.BooleanField(default=True)
    desktop_alerts = models.BooleanField(default=True)
    sensitivity = models.CharField(max_length=20, default='MEDIUM')
    auto_refresh_rate = models.IntegerField(default=5)  # in seconds
    promiscuous_mode = models.BooleanField(default=False)

    def __str__(self):
        return f"Settings for {self.user.username}"
