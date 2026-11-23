from django.test import TestCase
from django.contrib.auth.models import User
from django.urls import reverse
from apps.detection.models import DetectionRule
from .models import UserSettings


class UserSettingsTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='settings-test', password='password123'
        )
        self.client.login(username='settings-test', password='password123')

    def test_refresh_and_alert_preferences_are_saved(self):
        response = self.client.post(reverse('user_settings:settings'), {
            'sensitivity': 'HIGH',
            'auto_refresh_rate': '10',
            'sound_alerts': 'on',
            'desktop_alerts': 'on',
        })

        self.assertEqual(response.status_code, 200)
        settings = UserSettings.objects.get(user=self.user)
        self.assertEqual(settings.auto_refresh_rate, 10)
        self.assertTrue(settings.sound_alerts)
        self.assertTrue(settings.desktop_alerts)
        self.assertEqual(
            DetectionRule.objects.get(code='PORT_SCAN').threshold, 10
        )
        self.assertEqual(
            DetectionRule.objects.get(code='CONN_ATTEMPT').threshold, 10
        )
        self.assertEqual(
            DetectionRule.objects.get(code='DOS_BANDWIDTH').threshold, 25000000
        )

    def test_invalid_refresh_rate_does_not_save_settings(self):
        response = self.client.post(reverse('user_settings:settings'), {
            'sensitivity': 'HIGH',
            'auto_refresh_rate': '6',
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Choose a valid refresh interval')
        settings = UserSettings.objects.get(user=self.user)
        self.assertEqual(settings.auto_refresh_rate, 5)
        self.assertEqual(settings.sensitivity, 'MEDIUM')
