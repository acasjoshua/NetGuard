from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.contrib import messages
from apps.user_profile.models import Profile
from apps.user_settings.models import UserSettings
from apps.home.models import ActivityLog

def register_view(request):
    if request.user.is_authenticated:
        return redirect("home:home")

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        full_name = request.POST.get("full_name", "").strip()
        email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "")
        confirm_password = request.POST.get("confirm_password", "")
        role = request.POST.get("role", "Network Security Analyst")

        # Validation
        if not username or not password:
            return render(request, "register/register.html", {
                "error": "Username and password are required.",
                "form_data": request.POST
            })

        if len(username) < 3:
            return render(request, "register/register.html", {
                "error": "Username must be at least 3 characters long.",
                "form_data": request.POST
            })

        if len(password) < 6:
            return render(request, "register/register.html", {
                "error": "Password must be at least 6 characters long.",
                "form_data": request.POST
            })

        if password != confirm_password:
            return render(request, "register/register.html", {
                "error": "Passwords do not match.",
                "form_data": request.POST
            })

        if User.objects.filter(username=username).exists():
            return render(request, "register/register.html", {
                "error": f"The username '{username}' is already taken.",
                "form_data": request.POST
            })

        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=full_name.split()[0] if full_name else "",
            last_name=" ".join(full_name.split()[1:]) if len(full_name.split()) > 1 else ""
        )

        # Create associated Profile and Settings
        Profile.objects.create(
            user=user,
            full_name=full_name,
            role=role,
            email_contact=email,
            organization="NetGuard Security Operations",
            bio="Security enthusiast and network operator."
        )

        UserSettings.objects.create(
            user=user,
            dark_mode=True,
            email_notifications=True,
            sound_alerts=True,
            sensitivity="MEDIUM",
            auto_refresh_rate=5
        )

        ActivityLog.objects.create(
            action="New User Registered",
            category="AUTH",
            source_ip=request.META.get('REMOTE_ADDR', '127.0.0.1'),
            details=f"User '{username}' registered with role '{role}'.",
            user=user
        )

        # Redirect to login URL with a success message query parameter so form posts to /login/
        messages.success(request, "Registration successful! You may now sign in with your credentials.")
        return redirect("login:login")

    return render(request, "register/register.html")
