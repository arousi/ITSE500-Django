# API contract (`api/schema.yaml`)

This directory holds the **published OpenAPI contract** for Prompeteer
Server. It is the single source of truth that the Flutter and React client
repos generate their API clients/types from in a multi-repo sync — treat it
the same way you'd treat a versioned public API.

## This file is generated — do not hand-edit

`api/schema.yaml` is produced by `drf-spectacular` introspecting the live
Django/DRF views, serializers, and URL conf. Any manual edit will be silently
overwritten (and, separately, will start failing the CI `schema-drift` check,
which diffs a freshly generated copy against the committed file).

## Regenerating it

```bash
python manage.py spectacular --file api/schema.yaml
```

or, from the repo root:

```bash
make schema
```

Run this any time you change a view, serializer, or URL that affects the
public API surface, then commit the resulting `api/schema.yaml` diff in the
same PR as the code change. CI's `schema-drift` job will fail the build if
you forget.

## Consumers

- **Flutter client** — generates its Dart API client/models from this file.
- **React client** — generates its TypeScript API client/types from this file.

Both client repos pull `api/schema.yaml` from this repo as their contract
source. Breaking changes here are breaking changes for both clients — treat
API/contract changes with the same discipline as any other versioned public
interface (see the project's release-engineering conventions: additive
changes are safe to ship in place, breaking changes need a deprecation
window).

## Known gaps (expected, not failures)

Generating the schema today prints ~47 "unable to guess serializer" messages
for plain `APIView` subclasses that have no `serializer_class` (or matching
method) for `drf-spectacular` to introspect. These are **graceful fallbacks**
— the schema still generates successfully for every URL, just with a
best-effort (untyped) request/response body for those views. This is not a
CI failure condition.

### TODO — improve typed codegen quality

The following views are exercised by both clients and would benefit most
from explicit `@extend_schema` (and, where relevant, `serializer_class`)
annotations, so the generated Dart/TypeScript types are accurate instead of
falling back to untyped `object`:

- `auth_api` — `LoginView`, `RegisterView`, `LoginWithOTPView`, and the
  OAuth authorize/callback views (Google/GitHub/Microsoft/OpenRouter)
- `user_mang` — `UnifiedSyncView`
- `crypto_api` — `UserUMKView`

This annotation work is intentionally **out of scope** for this change (CI +
contract-publishing foundation only) and is tracked as a follow-up.
