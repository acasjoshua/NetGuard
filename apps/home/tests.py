import ipaddress
from itertools import islice
from datetime import timedelta

from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone
from apps.monitoring.models import Device
from apps.detection.models import SecurityAlert, DetectionRule
from apps.user_settings.models import UserSettings
from .ids_engine import (
    execute_rule_based_analysis,
    run_controlled_scenario,
    seed_sample_data_if_empty,
    get_default_network,
)

class WIDSIntrusionDetectionTests(TestCase):
    def setUp(self):
        # Create test analyst user
        self.user = User.objects.create_user(
            username='testanalyst',
            password='password123',
            email='test@netguard.local'
        )
        self.client = Client()
        seed_sample_data_if_empty()
        self.network = get_default_network()
        self.local_ips = [
            str(address)
            for address in islice(
                ipaddress.ip_network(self.network.subnet_cidr, strict=False).hosts(),
                24,
            )
        ]

    def test_authentication_login_logout(self):
        """Scope A: Test Login and Logout functionality."""
        login_success = self.client.login(username='testanalyst', password='password123')
        self.assertTrue(login_success)

        # Access dashboard
        response = self.client.get(reverse('home:home'))
        self.assertEqual(response.status_code, 200)

        # Logout
        response = self.client.get(reverse('login:logout'))
        self.assertEqual(response.status_code, 302)

    def test_demo_identity_query_and_cookie_do_not_authenticate(self):
        response = self.client.get(
            reverse('home:home'), {'as_user': 'acas'}
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('login:login'), response.url)

        self.client.cookies['demo_user'] = 'acas'
        response = self.client.get(reverse('home:home'))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('login:login'), response.url)

    def test_rule_01_port_scan_detection(self):
        """Scope D & Objective 2: Verify Rule 1 detects rapid port probing."""
        rule = DetectionRule.objects.get(code='PORT_SCAN')
        probes = [
            {
                'source_ip': self.local_ips[0],
                'destination_ip': str(self.network.gateway_ip),
                'destination_port': p,
                'packets': 1,
                'duration_seconds': min(2.0, float(rule.time_window_sec)),
            }
            for p in range(2000, 2000 + rule.threshold)
        ]
        result = execute_rule_based_analysis(probes)
        self.assertTrue(len(result['alerts_triggered']) > 0)
        port_scan_alerts = [a for a in result['alerts_triggered'] if a.event_type == 'PORT_SCAN']
        self.assertTrue(len(port_scan_alerts) > 0)
        self.assertEqual(port_scan_alerts[0].source_ip, self.local_ips[0])

    def test_port_scan_uses_configured_threshold_and_time_window(self):
        rule = DetectionRule.objects.get(code='PORT_SCAN')
        rule.threshold = 10
        rule.time_window_sec = 5
        rule.save()
        source_ip = self.local_ips[0]
        probes = [
            {
                'source_ip': source_ip,
                'destination_ip': str(self.network.gateway_ip),
                'destination_port': port,
                'duration_seconds': 4,
            }
            for port in range(3000, 3010)
        ]

        result = execute_rule_based_analysis(probes)
        self.assertIn('PORT_SCAN', [alert.event_type for alert in result['alerts_triggered']])

        for probe in probes:
            probe['duration_seconds'] = 6
        result = execute_rule_based_analysis(probes)
        self.assertNotIn('PORT_SCAN', [alert.event_type for alert in result['alerts_triggered']])

    def test_rule_02_connection_burst_detection(self):
        """Scope D & Objective 2: Verify Rule 2 detects excessive connection attempts."""
        rule = DetectionRule.objects.get(code='CONN_ATTEMPT')
        bursts = [
            {
                'source_ip': self.local_ips[0],
                'destination_ip': self.local_ips[1],
                'destination_port': 80,
                'packets': 1,
                'duration_seconds': min(3.0, float(rule.time_window_sec)),
            }
            for _ in range(rule.threshold)
        ]
        result = execute_rule_based_analysis(bursts)
        self.assertTrue(len(result['alerts_triggered']) > 0)
        burst_alerts = [a for a in result['alerts_triggered'] if a.event_type == 'CONN_ATTEMPT']
        self.assertTrue(len(burst_alerts) > 0)

    def test_rule_03_abnormal_traffic_detection(self):
        """Scope D & Objective 2: Verify Rule 3 uses its configured bps threshold."""
        rule = DetectionRule.objects.get(code='DOS_BANDWIDTH')
        traffic = [
            {
                'source_ip': self.local_ips[0],
                'destination_ip': str(self.network.gateway_ip),
                'destination_port': 443,
                'packets': 450,
                'bandwidth_bps': rule.threshold + 1,
                'duration_seconds': min(3.0, float(rule.time_window_sec)),
            }
        ]
        result = execute_rule_based_analysis(traffic)
        self.assertTrue(len(result['alerts_triggered']) > 0)
        abnormal_alerts = [a for a in result['alerts_triggered'] if a.event_type == 'DOS_BANDWIDTH']
        self.assertTrue(len(abnormal_alerts) > 0)

    def test_controlled_scenario_evaluation(self):
        """SMART Objective 6: Verify controlled scenario runner executes and logs results."""
        scenario_result = run_controlled_scenario('port_scan')
        self.assertEqual(scenario_result['verdict'], 'THREAT DETECTED')
        self.assertGreaterEqual(scenario_result['elapsed_ms'], 0.0)
        self.assertIn('PORT_SCAN', scenario_result['expected_rule'])

    def test_scenario_lab_exercises_each_enabled_detection_rule(self):
        scenarios = {
            'port_scan': 'PORT_SCAN',
            'host_scan': 'HOST_SCAN',
            'connection_burst': 'CONN_ATTEMPT',
            'abnormal_traffic': 'DOS_BANDWIDTH',
            'suspicious_port': 'UNAUTH_SERVICE',
        }
        for scenario_key, expected_rule in scenarios.items():
            with self.subTest(scenario=scenario_key):
                result = run_controlled_scenario(scenario_key)
                self.assertEqual(result['verdict'], 'THREAT DETECTED')
                self.assertIn(
                    expected_rule,
                    [alert.event_type for alert in result['alerts']],
                )

        baseline = run_controlled_scenario('baseline')
        self.assertEqual(baseline['verdict'], 'NORMAL / PASS')

    def test_host_scan_detection_uses_local_targets_and_rule_window(self):
        rule = DetectionRule.objects.get(code='HOST_SCAN')
        rule.threshold = 3
        rule.time_window_sec = 10
        rule.save()
        source_ip = self.local_ips[0]
        probes = [
            {
                'source_ip': source_ip,
                'destination_ip': target_ip,
                'destination_port': 8080,
                'duration_seconds': 5,
            }
            for target_ip in self.local_ips[1:4]
        ]

        result = execute_rule_based_analysis(probes)
        self.assertIn('HOST_SCAN', [alert.event_type for alert in result['alerts_triggered']])

        for probe in probes:
            probe['duration_seconds'] = 11
        result = execute_rule_based_analysis(probes)
        self.assertNotIn('HOST_SCAN', [alert.event_type for alert in result['alerts_triggered']])

    def test_scenarios_do_not_add_external_destinations_as_devices(self):
        for scenario in (
            'baseline', 'port_scan', 'host_scan', 'connection_burst',
            'abnormal_traffic', 'suspicious_port',
        ):
            run_controlled_scenario(scenario)

        subnet = ipaddress.ip_network(self.network.subnet_cidr, strict=False)
        for device in Device.objects.filter(network=self.network):
            self.assertIn(ipaddress.ip_address(device.ip_address), subnet)

        external_ip = next(
            candidate
            for candidate in ('203.0.113.250', '198.51.100.10', '192.0.2.10')
            if ipaddress.ip_address(candidate) not in subnet
        )
        result = execute_rule_based_analysis([
            {
                'source_ip': external_ip,
                'destination_ip': self.local_ips[0],
                'destination_port': 80,
                'packets': 1,
                'duration_seconds': 1,
            }
        ])
        self.assertEqual(result['events_ignored_outside_subnet'], 1)
        self.assertFalse(
            Device.objects.filter(network=self.network, ip_address=external_ip).exists()
        )

    def test_device_unknown_attributes_and_idle_status_are_truthful(self):
        device = Device.objects.filter(network=self.network).first()
        device.last_seen = timezone.now() - timedelta(minutes=6)
        device.save(update_fields=['last_seen'])

        self.assertEqual(device.status, 'Idle')
        self.assertEqual(device.vendor, 'Unknown')
        self.assertEqual(device.os_info, 'Not detected')
        self.assertEqual(device.open_ports, 'Not scanned')
        self.assertIsNone(device.packet_count)

    def test_device_page_hides_existing_out_of_subnet_records(self):
        subnet = ipaddress.ip_network(self.network.subnet_cidr, strict=False)
        external_ip = next(
            candidate
            for candidate in ('203.0.113.250', '198.51.100.10', '192.0.2.10')
            if ipaddress.ip_address(candidate) not in subnet
        )
        now = timezone.now()
        Device.objects.create(
            network=self.network,
            ip_address=external_ip,
            mac_address='02:AA:BB:CC:DD:EE',
            hostname='old-external-scenario-record',
            is_online=True,
            first_seen=now,
            last_seen=now,
        )
        self.client.login(username='testanalyst', password='password123')

        response = self.client.get(reverse('home:devices'))
        self.assertNotContains(response, external_ip)

    def test_subnet_scan_collects_live_when_available(self):
        self.client.login(username='testanalyst', password='password123')
        device = Device.objects.filter(network=self.network).first()
        old_last_seen = timezone.now() - timedelta(minutes=10)
        Device.objects.filter(pk=device.pk).update(last_seen=old_last_seen)

        response = self.client.post(reverse('home:api_scan_devices'))
        self.assertIn(response.status_code, (200, 503))
        self.assertIn(response.json()['status'], ('success', 'partial', 'error'))
        device.refresh_from_db()
        self.assertIsNotNone(device.last_seen)

    def test_dashboard_updates_use_user_settings_and_return_new_alerts(self):
        self.client.login(username='testanalyst', password='password123')
        UserSettings.objects.create(
            user=self.user,
            auto_refresh_rate=10,
            sound_alerts=False,
            desktop_alerts=True,
        )
        alert = SecurityAlert.objects.create(
            network=self.network,
            title='Notification test',
            message='A new test alert.',
        )

        response = self.client.get(
            reverse('home:api_traffic_stream'),
            {'after_id': alert.id - 1},
        )
        payload = response.json()
        self.assertTrue(payload['desktop_alerts'])
        self.assertFalse(payload['sound_alerts'])
        self.assertEqual([item['id'] for item in payload['new_alerts']], [alert.id])
        self.assertIn(payload['data_source'], ('live', 'unavailable'))

        dashboard = self.client.get(reverse('home:home'))
        self.assertContains(dashboard, 'data-refresh-interval="10"')

    def test_sidebar_alert_count_includes_only_unresolved_alerts(self):
        self.client.login(username='testanalyst', password='password123')
        for status in (
            SecurityAlert.Status.NEW,
            SecurityAlert.Status.ACKNOWLEDGED,
            SecurityAlert.Status.RESOLVED,
        ):
            SecurityAlert.objects.create(
                network=self.network,
                title=f'{status.label} sidebar test',
                message='Sidebar count test.',
                status=status,
            )

        response = self.client.get(reverse('home:alerts'))
        expected_count = SecurityAlert.objects.filter(
            network=self.network,
            status__in=[
                SecurityAlert.Status.NEW,
                SecurityAlert.Status.ACKNOWLEDGED,
            ],
        ).count()

        self.assertEqual(response.context['sidebar_alert_count'], expected_count)
        self.assertContains(
            response,
            f'id="sidebarAlertCount">{expected_count}</span>',
        )

    def test_report_generation(self):
        """Scope E.3: Verify generating security report computes dynamically."""
        self.client.login(username='testanalyst', password='password123')
        response = self.client.post(reverse('home:reports'), {
            'title': 'Test Evaluation Report',
            'period': 'Last 24 Hours'
        })
        self.assertEqual(response.status_code, 302)
        self.assertRegex(response.url, r'^/reports/\d+/')
