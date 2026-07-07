.PHONY: schema

# Regenerate the published OpenAPI contract (api/schema.yaml).
#
# This is the single command used to keep the contract in sync locally,
# referenced by:
#   - the CI `schema-drift` job (.github/workflows/ci.yml), which regenerates
#     to a temp file and diffs it against the committed api/schema.yaml
#   - the Flutter and React client repos, as the documented way to refresh
#     their generated API client/types after a backend change
#
# Run this after changing any view, serializer, or URL that affects the
# public API surface, then commit the resulting api/schema.yaml diff.
schema:
	python manage.py spectacular --file api/schema.yaml
