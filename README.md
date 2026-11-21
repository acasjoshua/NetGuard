# NetGuard

NetGuard is a Django-based local network monitoring and rule-based intrusion detection application. It presents device and traffic information in an operations dashboard and records security alerts and event logs.

## Features

- Designated local network overview with endpoint inventory and live traffic statistics
- Rule-based intrusion detection engine mapped to physical ERD relational schema
- Security alerts, detected events, dynamic report generation, and controlled testing scenarios
- Operator registration, authentication, profile management, and configurable user settings
- Seed command for sample network endpoints, telemetry, rules, and operator accounts

## Technology

- Python 3.9+
- Django 4.2
- PostgreSQL (Supabase)
- Chart.js for dashboard visualizations

## Setup

Run these commands from the cloned repository root. Ensure your `.env` file contains your Supabase PostgreSQL connection string in `DATABASE_URL`.

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

NetGuard is a passive, local-network demonstration. Its rule engine uses thresholds and signatures rather than machine learning, does not inspect encrypted payload contents, and does not block or disconnect devices. Low-level packet capture and ARP enumeration may require operating-system privileges and are outside the scope of the seeded demonstration data.
