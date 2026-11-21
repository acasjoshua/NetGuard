from django.contrib import admin

from .models import AllowedService, Network, UserNetwork


class AllowedServiceInline(admin.TabularInline):
    model = AllowedService
    extra = 0


@admin.register(Network)
class NetworkAdmin(admin.ModelAdmin):
    list_display = ("name", "subnet_cidr", "gateway_ip", "area", "connection_status", "last_scanned_at")
    list_filter = ("connection_status", "area")
    search_fields = ("name", "subnet_cidr", "area")
    inlines = [AllowedServiceInline]


@admin.register(UserNetwork)
class UserNetworkAdmin(admin.ModelAdmin):
    list_display = ("user", "network", "role", "added_at")
    list_filter = ("role",)


@admin.register(AllowedService)
class AllowedServiceAdmin(admin.ModelAdmin):
    list_display = ("network", "port", "protocol", "service_name")
    list_filter = ("protocol",)
