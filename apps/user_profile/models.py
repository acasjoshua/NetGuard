from django.contrib.auth.models import User
from django.db import models

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    full_name = models.CharField(max_length=150, blank=True)
    bio = models.TextField(blank=True)
    organization = models.CharField(max_length=150, blank=True, default='WIDS Operations')
    role = models.CharField(max_length=100, default='Network Security Analyst')
    email_contact = models.EmailField(max_length=150, blank=True)
    avatar_color = models.CharField(max_length=20, default='#06b6d4')

    def __str__(self):
        return f"{self.user.username} ({self.full_name or 'No name'})"
