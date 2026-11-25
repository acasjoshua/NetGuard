from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect
from django.core.cache import cache

def login_view(request):
    if request.user.is_authenticated:
        return redirect("home:home")

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")
        throttle_key = f"netguard-login:{request.META.get('REMOTE_ADDR', 'unknown')}:{username.casefold()}"
        if cache.get(throttle_key, 0) >= 5:
            return render(request, "login/login.html", {
                "error": "Too many failed attempts. Try again after one minute.",
                "last_username": username,
            }, status=429)

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
            cache.delete(throttle_key)
            login(request, user)
            next_url = request.GET.get("next")
            if next_url:
                return redirect(next_url)
            return redirect("home:home")
        else:
            cache.set(throttle_key, cache.get(throttle_key, 0) + 1, timeout=60)
            return render(request, "login/login.html", {
                "error": "Invalid username or password. Please try again.",
                "last_username": username
            })

    return render(request, "login/login.html")

def logout_view(request):
    logout(request)
    return redirect("login:login")
