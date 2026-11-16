from django.urls import path
from . import views

app_name = "home"

urlpatterns = [
    path("", views.home_view, name="home"),
    path("devices/", views.devices_view, name="devices"),
    path("alerts/", views.alerts_view, name="alerts"),
    path("logs/", views.logs_view, name="logs"),
    path("reports/", views.reports_view, name="reports"),
    path("reports/<int:report_id>/", views.report_detail_view, name="report_detail"),
    path("scenarios/", views.controlled_scenarios_view, name="scenarios"),
    # API endpoints
    path("api/traffic-stream/", views.api_traffic_stream, name="api_traffic_stream"),
    path("api/resolve-alert/<int:alert_id>/", views.api_resolve_alert, name="api_resolve_alert"),
    path("api/scan-devices/", views.api_scan_devices, name="api_scan_devices"),
]
