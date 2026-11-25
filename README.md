# WIDS

WIDS (Wandering Intrusion Detection System) is a Django-based rule-driven network-monitoring demonstration. It includes live interface counters, bounded ping/ARP discovery, and common TCP-port checks, while seeded inventory and synthetic scenario events remain available for evaluation.

## Features

- Configured subnet overview with live interface discovery where supported, plus clearly labeled sample records
- Rule-based evaluation of generated events, using stored thresholds and time windows
- Security alerts, detected events, dynamic report generation, and controlled testing scenarios
- Operator registration, authentication, profile management, and configurable user settings
- Seed command for sample network endpoints, telemetry, rules, and operator accounts

Device role, vendor, operating system, and open-port information is labeled unknown or
not scanned unless a live collection component supplies verified values. Live discovery
uses bounded ping/ARP and common-port checks; it is not packet payload inspection.

## Technology

- Python 3.9+
- Django 4.2
- PostgreSQL (Supabase)
- Chart.js for dashboard visualizations

## Setup

Run these commands from the cloned repository root. Ensure your `.env` file contains your Supabase PostgreSQL connection string in `DATABASE_URL`.
For deployment, set `DJANGO_ALLOWED_HOSTS` to a comma-separated list of the hostnames
that serve the application. For local development with Django's `runserver`, add
`DJANGO_DEBUG=True` to `.env` so Django serves static assets. Debug mode is disabled
by default and should remain disabled in production, where static files must be served
by the deployment's static-file server.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python manage.py migrate
python manage.py seed_netguard
python manage.py runserver 127.0.0.1:8080
```

Open <http://127.0.0.1:8080/> in a browser. On macOS or Linux, activate the environment with `source .venv/bin/activate` instead.

Operator accounts can be created via the registration interface (`/register/`) or initialized via `seed_netguard`. Demo account passwords should be supplied via environment variables (`NETGUARD_ADMIN_PASSWORD` and `NETGUARD_ACAS_PASSWORD`) before deploying.

## Project Layout

```text
apps/
  networks/      Network subnet topology, user mappings, and allowed services
  monitoring/    Monitored network devices and bandwidth telemetry
  detection/     Intrusion detection rules, security alerts, and detected events
  home/          Dashboard, monitoring views, detection engine, and scenarios
  login/         Authentication and session management
  register/      Operator registration
  user_profile/  Profile management
  user_settings/ Detection sensitivity and display preferences
config/          Django project configuration
static/          CSS, JavaScript, and image assets
templates/       Django templates
manage.py        Django management entry point
```

## Verification

Run the Django checks and tests from the repository root:

```powershell
python manage.py check
python manage.py test --keepdb
```

## Limitations

WIDS collects host-interface counters and bounded local-subnet inventory when permitted.
Seeded device records and synthetic scenario events remain examples, not proof of live
incidents. Full packet capture, payload inspection, OS/vendor fingerprinting, protocol
distribution, email delivery, and device blocking are not implemented.
