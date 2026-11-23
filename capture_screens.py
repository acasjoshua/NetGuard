import os
import sys
import django
import subprocess
from pathlib import Path

# Setup Django environment
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from django.test import Client
from apps.home.ids_engine import seed_sample_data_if_empty
seed_sample_data_if_empty()

client = Client()

# Target screenshots directory
ROOT_DIR = BASE_DIR.parent
APP_SCREENSHOTS_DIR = ROOT_DIR / "APPLICATION_SCREENSHOTS"
APP_SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)
TEMP_HTML_DIR = BASE_DIR / "temp_rendered_screens"
TEMP_HTML_DIR.mkdir(parents=True, exist_ok=True)

static_abs_uri = (BASE_DIR / "static").as_uri()

screens = [
    ("01_Login.png", "/login/"),
    ("02_Dashboard.png", "/"),
    ("03_ConnectedDevices.png", "/devices/"),
    ("04_SecurityAlerts.png", "/alerts/"),
    ("05_ScenarioTestingLab.png", "/scenarios/"),
    ("06_EventLogs.png", "/logs/"),
    ("07_Reports.png", "/reports/"),
    ("08_UserManagement_Profile.png", "/profile/"),
    ("09_Settings.png", "/settings/"),
    ("10_Register.png", "/register/"),
]

edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
if not os.path.exists(edge_path):
    edge_path = r"C:\Program Files\Google\Chrome\Application\chrome.exe"

print(f"Using browser: {edge_path}")

for index, (filename, url) in enumerate(screens):
    if index == 1 and not client.login(
        username=os.environ.get("NETGUARD_SCREENSHOT_USERNAME", "acas"),
        password=os.environ.get("NETGUARD_SCREENSHOT_PASSWORD", "acas123"),
    ):
        raise RuntimeError(
            "Could not authenticate screenshot client. Seed the demo user or set "
            "NETGUARD_SCREENSHOT_USERNAME and NETGUARD_SCREENSHOT_PASSWORD."
        )

    res = client.get(url, follow=True)
    if res.status_code == 200:
        html = res.content.decode('utf-8', errors='ignore')
        # Replace static path with absolute file URI so browser loads all CSS/JS
        html = html.replace('href="/static/', f'href="{static_abs_uri}/')
        html = html.replace('src="/static/', f'src="{static_abs_uri}/')
        html = html.replace("href='/static/", f"href='{static_abs_uri}/")
        html = html.replace("src='/static/", f"src='{static_abs_uri}/")

        temp_html_path = TEMP_HTML_DIR / f"{Path(filename).stem}.html"
        with open(temp_html_path, "w", encoding="utf-8") as f:
            f.write(html)

        png_output_path = APP_SCREENSHOTS_DIR / filename
        cmd = [
            edge_path,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--window-size=1440,900",
            f"--screenshot={png_output_path}",
            temp_html_path.as_uri(),
        ]
        print(f"Capturing {filename}...")
        subprocess.run(cmd, capture_output=True)
        if png_output_path.exists() and png_output_path.stat().st_size > 0:
            print(f" -> OK: {filename} ({png_output_path.stat().st_size} bytes)")
        else:
            print(f" -> FAILED: {filename}")
    else:
        print(f"Failed to fetch {url}: status {res.status_code}")

print("\nScreenshot generation process completed!")
