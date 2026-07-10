"""Project-wide admin configuration.

Autodiscovered because ``prompeteer_server`` is in INSTALLED_APPS. This module
does NOT register models (each app owns its own ModelAdmins) — it adds
cross-cutting behaviour to the whole admin site:

- a site-wide "Export selected as CSV" action available on every model's
  changelist (project models and Django built-ins alike);
- admin branding (header/title/index title) as the Django-native fallback that
  applies even if jazzmin is ever removed.
"""
from __future__ import annotations

import csv

from django.contrib import admin
from django.http import HttpResponse


@admin.action(description="Export selected as CSV")
def export_as_csv(modeladmin, request, queryset):
    """Stream the selected rows as a CSV of their concrete model fields.

    Registered site-wide (below) so it shows up on every changelist. Uses each
    model's concrete local fields — FKs are exported by their raw id via
    ``<field>_id`` (attname), which keeps the export flat and avoids triggering
    a query per related object.
    """
    model = modeladmin.model
    meta = model._meta
    field_names = [f.name for f in meta.fields]

    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = f"attachment; filename={meta.label_lower.replace('.', '_')}.csv"

    writer = csv.writer(response)
    writer.writerow(field_names)
    for obj in queryset:
        row = []
        for field in meta.fields:
            value = getattr(obj, field.attname, "")
            row.append("" if value is None else str(value))
        writer.writerow(row)
    return response


# Make CSV export available on EVERY model in the admin, not just ones that opt
# in. Per-model `actions` tuples still work alongside this global action.
admin.site.add_action(export_as_csv)

# Django-native branding (jazzmin overrides these with its own settings when
# installed, but keeping them means the admin stays branded without jazzmin).
admin.site.site_header = "ITSE500 / Prompeteer Administration"
admin.site.site_title = "ITSE500 Admin"
admin.site.index_title = "Platform administration"
