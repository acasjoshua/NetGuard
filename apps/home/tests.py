from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from apps.monitoring.models import Device, TrafficStat
from apps.detection.models import SecurityAlert, DetectionRule, DetectedEvent
from apps.networks.models import Network
from .ids_engine import execute_rule_based_analysis, run_controlled_scenario, seed_sample_data_if_empty, get_default_network

class NetGuardIntrusionDetectionTests(TestCase):
    def setUp(self):
        # Create test analyst user
        self.user = User.objects.create_user(
            username='testanalyst',
            password='password123',
            email='test@netguard.local'
        )
        self.client = Client()
        seed_sample_data_if_empty()

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

    def test_rule_01_port_scan_detection(self):
        """Scope D & Objective 2: Verify Rule 1 detects rapid port probing."""
        probes = [
            {'source_ip': '192.168.1.99', 'destination_ip': '192.168.1.1', 'destination_port': p, 'packets': 1, 'duration_seconds': 2.0}
            for p in [21, 22, 23, 25, 80, 110, 135, 443, 445, 8080]
        ]
        result = execute_rule_based_analysis(probes)
        self.assertTrue(len(result['alerts_triggered']) > 0)
        port_scan_alerts = [a for a in result['alerts_triggered'] if a.event_type == 'PORT_SCAN']
        self.assertTrue(len(port_scan_alerts) > 0)
        self.assertEqual(port_scan_alerts[0].source_ip, '192.168.1.99')

    def test_rule_02_connection_burst_detection(self):
        """Scope D & Objective 2: Verify Rule 2 detects excessive connection attempts."""
        bursts = [
            {'source_ip': '192.168.1.101', 'destination_ip': '192.168.1.120', 'destination_port': 80, 'packets': 1, 'duration_seconds': 3.0}
            for _ in range(45)
        ]
        result = execute_rule_based_analysis(bursts)
        self.assertTrue(len(result['alerts_triggered']) > 0)
        burst_alerts = [a for a in result['alerts_triggered'] if a.event_type == 'CONN_ATTEMPT']
        self.assertTrue(len(burst_alerts) > 0)

    def test_rule_03_abnormal_traffic_detection(self):
        """Scope D & Objective 2: Verify Rule 3 detects high packet rate surges."""
        traffic = [
            {'source_ip': '192.168.1.102', 'destination_ip': '192.168.1.1', 'destination_port': 443, 'packets': 450, 'duration_seconds': 3.0}
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

    def test_report_generation(self):
        """Scope E.3: Verify generating security report computes dynamically."""
        self.client.login(username='testanalyst', password='password123')
        response = self.client.post(reverse('home:reports'), {
            'title': 'Test Evaluation Report',
            'period': 'Last 24 Hours'
        })
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse('home:report_detail', kwargs={'report_id': 1}), response.url)
