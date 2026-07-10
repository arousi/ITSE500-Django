#!/usr/bin/env python
"""Fail if any project model (auth_api/user_mang/chat_api/crypto_api) lacks an
admin registration. Run inside the image:

    python manage.py shell < scripts/check_admin_coverage.py
"""
from django.apps import apps
from django.contrib import admin

PROJECT_APPS = {"auth_api", "user_mang", "chat_api", "crypto_api"}

registered = set(admin.site._registry.keys())
missing = []
covered = []
for model in apps.get_models():
    if model._meta.app_label not in PROJECT_APPS:
        continue
    label = f"{model._meta.app_label}.{model.__name__}"
    if model in registered:
        covered.append(label)
    else:
        missing.append(label)

print("COVERED:", ", ".join(sorted(covered)) or "(none)")
print("MISSING:", ", ".join(sorted(missing)) or "(none)")
print("RESULT:", "ALL_REGISTERED" if not missing else "GAPS_FOUND")
