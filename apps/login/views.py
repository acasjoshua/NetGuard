from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from apps.home.models import ActivityLog

def login_view(request):
    if request.user.is_authenticated:
        return redirect("home:home")

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")

        # Try authenticating directly by username
        user = authenticate(request, username=username, password=password)

        # If not matched, try authenticating using email as username
        if user is None and "@" in username:
            from django.contrib.auth.models import User
            try:
                matched_user = User.objects.get(email__iexact=username)
                user = authenticate(request, username=matched_user.username, password=password)
            except Exception:
                user = None
        if user is not None:
            login(request, user)
            ActivityLog.objects.create(
                action="User Login Successful",
                category="AUTH",
                source_ip=request.META.get('REMOTE_ADDR', '127.0.0.1'),
                details=f"User '{username}' logged in successfully.",
                user=user,
            )
            next_url = request.GET.get("next")
            if next_url:
                return redirect(next_url)
            return redirect("home:home")
        else:
            ActivityLog.objects.create(
                action="Failed Login Attempt",
                category="AUTH",
                source_ip=request.META.get('REMOTE_ADDR', '127.0.0.1'),
                details=f"Failed login attempt for username '{username}'.",
            )
            return render(request, "login/login.html", {
                "error": "Invalid username or password. Please try again.",
                "last_username": username
            })

    return render(request, "login/login.html")

def logout_view(request):
    if request.user.is_authenticated:
        ActivityLog.objects.create(
            action="User Logout",
            category="AUTH",
            source_ip=request.META.get('REMOTE_ADDR', '127.0.0.1'),
            details=f"User '{request.user.username}' logged out.",
            user=request.user,
        )
    logout(request)
    return redirect("login:login")
