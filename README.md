# NetGuard

NetGuard is a Django-based demonstration of rule-based network intrusion detection. The current application uses seeded sample inventory, generated traffic telemetry, and synthetic scenario events; it does not collect live packets, perform ARP discovery, or scan device ports.

## Features

- Configured subnet overview with sample endpoint inventory and simulated traffic statistics
- Rule-based evaluation of generated events, using stored thresholds and time windows
- Security alerts, detected events, dynamic report generation, and controlled testing scenarios
- Operator registration, authentication, profile management, and configurable user settings
- Seed command for sample network endpoints, telemetry, rules, and operator accounts

Device role, vendor, operating system, and open-port information is shown as unknown or
not scanned unless a future data-collection component supplies verified values. The
"Live Discovery Unavailable" action is intentional; the app does not claim to scan a
subnet or refresh host activity.

## Technology

- Python 3.9+
- Django 4.2
- PostgreSQL (Supabase)
- Chart.js for dashboard visualizations

## Setup

Run these commands from the cloned repository root. Ensure your `.env` file contains your Supabase PostgreSQL connection string in `DATABASE_URL`.
For deployment, set `DJANGO_ALLOWED_HOSTS` to a comma-separated list of the hostnames
that serve the application. Debug mode is disabled by default; enable it locally only
with `DJANGO_DEBUG=True`.

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

NetGuard currently does not collect live network telemetry. Seeded device records and
traffic snapshots are examples, dashboard stream values are generated, and scenario
events are synthetic. Rule results validate the engine against these generated inputs
only; they are not evidence of observed network activity. ARP discovery, packet capture,
port scanning, OS/vendor detection, email delivery, and device blocking are not
implemented. The network subnet is an application configuration/hostname-derived
approximation, not a verified interface configuration.
