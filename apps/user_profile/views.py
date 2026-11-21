from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Profile

@login_required
def profile_view(request):
    profile, created = Profile.objects.get_or_create(
        user=request.user,
        defaults={
            'full_name': f"{request.user.first_name} {request.user.last_name}".strip() or request.user.username,
            'role': 'Network Security Analyst',
            'organization': 'NetGuard Security Operations',
            'email_contact': request.user.email,
        }
    )

    success_msg = None
    if request.method == "POST":
        profile.full_name = request.POST.get("full_name", "").strip()
        profile.email_contact = request.POST.get("email_contact", "").strip()
        profile.organization = request.POST.get("organization", "").strip()
        profile.role = request.POST.get("role", "").strip()
        profile.bio = request.POST.get("bio", "").strip()
        profile.avatar_color = request.POST.get("avatar_color", profile.avatar_color)
        profile.save()

        # Update User model email and name as well
        if profile.email_contact:
            request.user.email = profile.email_contact
        names = profile.full_name.split()
        if names:
            request.user.first_name = names[0]
            request.user.last_name = " ".join(names[1:]) if len(names) > 1 else ""
        request.user.save()
        success_msg = "Profile updated successfully!"

    context = {
        "profile": profile,
        "success_msg": success_msg,
    }
    return render(request, "profile/profile.html", context)
