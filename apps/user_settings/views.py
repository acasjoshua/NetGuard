from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from .models import UserSettings
from apps.detection.models import DetectionRule

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
            DetectionRule.objects.filter(code='PORT_SCAN').update(threshold=10)
            DetectionRule.objects.filter(code='CONN_ATTEMPT').update(threshold=10)
            DetectionRule.objects.filter(code='DOS_BANDWIDTH').update(threshold=25000000)
        elif settings_obj.sensitivity == 'LOW':
            DetectionRule.objects.filter(code='PORT_SCAN').update(threshold=25)
            DetectionRule.objects.filter(code='CONN_ATTEMPT').update(threshold=35)
            DetectionRule.objects.filter(code='DOS_BANDWIDTH').update(threshold=80000000)
        else: # MEDIUM
            DetectionRule.objects.filter(code='PORT_SCAN').update(threshold=15)
            DetectionRule.objects.filter(code='CONN_ATTEMPT').update(threshold=20)
            DetectionRule.objects.filter(code='DOS_BANDWIDTH').update(threshold=50000000)

        success_msg = "Settings and detection thresholds updated successfully!"

    rules = DetectionRule.objects.all()

    context = {
        "settings": settings_obj,
        "rules": rules,
        "success_msg": success_msg,
    }
    return render(request, "user_settings/settings.html", context)
