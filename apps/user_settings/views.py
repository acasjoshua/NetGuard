from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import UserSettings
from apps.detection.models import DetectionRule

@login_required
def settings_view(request):
    settings_obj, _ = UserSettings.objects.get_or_create(
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
    error_msg = None
    if request.method == "POST":
        try:
            refresh_rate = int(request.POST.get("auto_refresh_rate", ""))
        except ValueError:
            refresh_rate = None

        sensitivity = request.POST.get("sensitivity", "")
        if refresh_rate not in {3, 5, 10, 30} or sensitivity not in {"LOW", "MEDIUM", "HIGH"}:
            error_msg = "Choose a valid refresh interval and detection sensitivity."
        else:
            settings_obj.dark_mode = "dark_mode" in request.POST
            settings_obj.sound_alerts = "sound_alerts" in request.POST
            settings_obj.desktop_alerts = "desktop_alerts" in request.POST
            settings_obj.sensitivity = sensitivity
            settings_obj.promiscuous_mode = "promiscuous_mode" in request.POST
            settings_obj.auto_refresh_rate = refresh_rate
            settings_obj.save()

            if sensitivity == 'HIGH':
                DetectionRule.objects.filter(code='PORT_SCAN').update(threshold=10)
                DetectionRule.objects.filter(code='CONN_ATTEMPT').update(threshold=10)
                DetectionRule.objects.filter(code='DOS_BANDWIDTH').update(threshold=25000000)
            elif sensitivity == 'LOW':
                DetectionRule.objects.filter(code='PORT_SCAN').update(threshold=25)
                DetectionRule.objects.filter(code='CONN_ATTEMPT').update(threshold=35)
                DetectionRule.objects.filter(code='DOS_BANDWIDTH').update(threshold=80000000)
            else:
                DetectionRule.objects.filter(code='PORT_SCAN').update(threshold=15)
                DetectionRule.objects.filter(code='CONN_ATTEMPT').update(threshold=20)
                DetectionRule.objects.filter(code='DOS_BANDWIDTH').update(threshold=50000000)

            success_msg = "Settings and detection thresholds updated successfully!"

    rules = DetectionRule.objects.all()

    context = {
        "settings": settings_obj,
        "rules": rules,
        "success_msg": success_msg,
        "error_msg": error_msg,
    }
    return render(request, "user_settings/settings.html", context)
