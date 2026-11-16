from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from apps.user_profile.models import Profile
from apps.user_settings.models import UserSettings
from apps.home.ids_engine import seed_sample_data_if_empty

class Command(BaseCommand):
    help = 'Seed initial NetGuard users, detection rules, devices, and baseline telemetry'

    def handle(self, *args, **options):
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
            admin_user.set_password('admin123')
            admin_user.save()
            self.stdout.write(self.style.SUCCESS('Created admin user (admin / admin123)'))

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
            acas_user.set_password('acas123')
            acas_user.save()
            self.stdout.write(self.style.SUCCESS('Created user acas (acas / acas123)'))

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

        # 3. Seed data
        seed_sample_data_if_empty()
        self.stdout.write(self.style.SUCCESS('NetGuard sample devices, rules, snapshots, and alerts seeded successfully.'))
