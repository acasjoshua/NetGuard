from django.core.management.base import BaseCommand
import os
from django.contrib.auth.models import User
from apps.user_profile.models import Profile
from apps.user_settings.models import UserSettings
from apps.networks.models import UserNetwork
from apps.home.ids_engine import seed_sample_data_if_empty, get_default_network

class Command(BaseCommand):
    help = 'Seed initial NetGuard users, detection rules, devices, and baseline telemetry'

    def handle(self, *args, **options):
        network = get_default_network()

        # 1. Create or get admin user
        admin_user, created = User.objects.get_or_create(
            username='admin',
            defaults={
                'email': 'admin@netguard.local',
                'first_name': 'System',
                'last_name': 'Administrator',
                'is_staff': True,
                'is_superuser': True,
            }
        )
        if created:
            admin_password = os.environ.get("NETGUARD_ADMIN_PASSWORD", "change-me-now")
            admin_user.set_password(admin_password)
            admin_user.save()
            self.stdout.write(self.style.SUCCESS(
                'Created admin user (set NETGUARD_ADMIN_PASSWORD for deployment)'
            ))

        Profile.objects.get_or_create(
            user=admin_user,
            defaults={
                'full_name': 'System Administrator',
                'role': 'Lead Security Architect',
                'organization': 'NetGuard Security Team',
                'bio': 'System administrator and security lead monitoring designated local network subnets.',
                'email_contact': 'admin@netguard.local',
                'avatar_color': '#6366f1'
            }
        )

        UserSettings.objects.get_or_create(
            user=admin_user,
            defaults={
                'dark_mode': True,
                'email_notifications': True,
                'sound_alerts': True,
                'sensitivity': 'MEDIUM',
                'auto_refresh_rate': 5,
            }
        )

        UserNetwork.objects.get_or_create(
            user=admin_user,
            network=network,
            defaults={'role': UserNetwork.Role.OWNER}
        )

        # 2. Create student user 'acas'
        acas_user, created = User.objects.get_or_create(
            username='acas',
            defaults={
                'email': 'acas@student.edu',
                'first_name': 'Security',
                'last_name': 'Acas',
                'is_staff': True,
            }
        )
        if created:
            acas_password = os.environ.get("NETGUARD_ACAS_PASSWORD", "change-me-now")
            acas_user.set_password(acas_password)
            acas_user.save()
            self.stdout.write(self.style.SUCCESS(
                'Created acas user (set NETGUARD_ACAS_PASSWORD for deployment)'
            ))

        Profile.objects.get_or_create(
            user=acas_user,
            defaults={
                'full_name': 'Security Analyst Acas',
                'role': 'Network Security Analyst',
                'organization': 'NetGuard Security Lab',
                'bio': 'Student researcher evaluating local network intrusion detection scenarios.',
                'email_contact': 'acas@student.edu',
                'avatar_color': '#06b6d4'
            }
        )

        UserSettings.objects.get_or_create(
            user=acas_user,
            defaults={
                'dark_mode': True,
                'email_notifications': True,
                'sound_alerts': True,
                'sensitivity': 'MEDIUM',
                'auto_refresh_rate': 5,
            }
        )

        UserNetwork.objects.get_or_create(
            user=acas_user,
            network=network,
            defaults={'role': UserNetwork.Role.SAVED}
        )

        # 3. Seed data
        seed_sample_data_if_empty()
        self.stdout.write(self.style.SUCCESS('NetGuard sample devices, rules, snapshots, and alerts seeded successfully.'))
