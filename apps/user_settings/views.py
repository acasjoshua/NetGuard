from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from .models import UserSettings
from apps.home.models import ActivityLog, DetectionRule

@login_required
def settings_view(request):
    settings_obj, created = UserSettings.objects.get_or_create(
        user=request.user,
        defaults={
            'dark_mode': True,
            'email_notifications': True,
            'sound_alerts': True,
            'desktop_alerts': True,
            'sensitivity': 'MEDIUM',
            'auto_refresh_rate': 5,
        }
    )

    success_msg = None
    if request.method == "POST":
        settings_obj.dark_mode = "dark_mode" in request.POST
        settings_obj.email_notifications = "email_notifications" in request.POST
        settings_obj.sound_alerts = "sound_alerts" in request.POST
        settings_obj.desktop_alerts = "desktop_alerts" in request.POST
        settings_obj.sensitivity = request.POST.get("sensitivity", "MEDIUM")
        settings_obj.promiscuous_mode = "promiscuous_mode" in request.POST

        try:
            settings_obj.auto_refresh_rate = int(request.POST.get("auto_refresh_rate", 5))
        except ValueError:
            settings_obj.auto_refresh_rate = 5

        settings_obj.save()

        # Adjust rule thresholds based on sensitivity
        if settings_obj.sensitivity == 'HIGH':
            DetectionRule.objects.filter(code='RULE-01').update(threshold_value=5.0)
            DetectionRule.objects.filter(code='RULE-02').update(threshold_value=20.0)
            DetectionRule.objects.filter(code='RULE-03').update(threshold_value=70.0)
        elif settings_obj.sensitivity == 'LOW':
            DetectionRule.objects.filter(code='RULE-01').update(threshold_value=12.0)
            DetectionRule.objects.filter(code='RULE-02').update(threshold_value=50.0)
            DetectionRule.objects.filter(code='RULE-03').update(threshold_value=150.0)
        else: # MEDIUM
            DetectionRule.objects.filter(code='RULE-01').update(threshold_value=8.0)
            DetectionRule.objects.filter(code='RULE-02').update(threshold_value=35.0)
            DetectionRule.objects.filter(code='RULE-03').update(threshold_value=100.0)

        ActivityLog.objects.create(
            action="System Settings Updated",
            category="SYSTEM",
            source_ip=request.META.get('REMOTE_ADDR', '127.0.0.1'),
            details=f"User {request.user.username} modified detection sensitivity to {settings_obj.sensitivity}.",
            user=request.user
        )
        success_msg = "Settings and detection thresholds updated successfully!"

    rules = DetectionRule.objects.all()

    context = {
        "settings": settings_obj,
        "rules": rules,
        "success_msg": success_msg,
    }
    return render(request, "user_settings/settings.html", context)
