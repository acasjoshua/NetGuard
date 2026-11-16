# NetGuard

NetGuard is a Django-based local network monitoring and rule-based intrusion detection application. It presents device and traffic information in an operations dashboard and records security alerts, event logs, and reports.

## Features

- Network overview with device inventory, traffic statistics, and protocol breakdowns
- Detection rules for rapid port scans, connection bursts, abnormal traffic rates, and legacy service probes
- Alerts, event logs, reports, and a controlled scenario-testing lab
- Operator registration, authentication, profile management, and configurable settings
- Seed command for sample devices, telemetry, rules, and demo accounts

## Technology

- Python 3.9+
- Django 4.2
- SQLite by default
- Chart.js for dashboard visualizations

## Setup

Run these commands from the cloned repository root.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python manage.py migrate
python manage.py seed_netguard
python manage.py runserver 127.0.0.1:8080
```

Open <http://127.0.0.1:8080/> in a browser. On macOS or Linux, activate the environment with `source .venv/bin/activate` instead.

The seed command creates demo accounts:

- Student Analyst: `acas` / `acas123`
- Lead Architect: `admin` / `admin123`

These credentials are for local demonstration only. Change or remove them before deploying the application.

## Detection Rules

- **RULE-01: Rapid port scan.** Flags a host targeting at least 8 distinct ports within 15 seconds.
- **RULE-02: Excessive connection rate.** Flags at least 35 socket connections from an IP within 10 seconds.
- **RULE-03: Abnormal traffic spike.** Flags traffic above 100 packets per second.
- **RULE-04: Legacy service probe.** Flags connection attempts to selected ports including Telnet (23), MS-RPC (135), and SMB (445).

Thresholds are rule-based and may require tuning for a real network. Scenario results are demonstrations, not a guarantee of threat detection.

## Project Layout

```text
apps/
  home/          Dashboard, monitoring data, detection engine, and scenarios
  login/         Authentication
  register/      Operator registration
  user_profile/  Profile management
  user_settings/ Detection and display preferences
config/          Django project configuration
static/          CSS, JavaScript, and image assets
templates/       Django templates
manage.py        Django management entry point
```

## Verification

Run the Django checks and tests from the repository root:

```powershell
python manage.py check
python manage.py test
```

## Limitations

NetGuard is a passive, local-network demonstration. Its rule engine uses thresholds and signatures rather than machine learning, does not inspect encrypted payload contents, and does not block or disconnect devices. Low-level packet capture and ARP enumeration may require operating-system privileges and are outside the scope of the seeded demonstration data.
