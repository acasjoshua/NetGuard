from apps.detection.models import SecurityAlert


def sidebar_alert_count(request):
    if not request.user.is_authenticated:
        return {"sidebar_alert_count": 0}

    network_id = request.session.get("active_network_id")
    user_networks = request.user.network_links.all()
    if network_id and not user_networks.filter(network_id=network_id).exists():
        network_id = None

    if network_id is None:
        network_id = (
            user_networks.order_by("-role", "network__name")
            .values_list("network_id", flat=True)
            .first()
        )

    if network_id is None:
        return {"sidebar_alert_count": 0}

    count = SecurityAlert.objects.filter(
        network_id=network_id,
        status__in=[
            SecurityAlert.Status.NEW,
            SecurityAlert.Status.ACKNOWLEDGED,
        ],
    ).count()
    return {"sidebar_alert_count": count}
