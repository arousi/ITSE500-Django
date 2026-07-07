# Legacy tests (quarantined — do not collect)

These test modules were written against a **pre-refactor** API surface and no
longer match the current codebase. They are kept here for reference only and
are excluded from pytest collection (see `pytest.ini` at the repo root,
`norecursedirs`).

| File | Predates | Broken because |
|---|---|---|
| `auth_api_test_views_comprehensive.py` | the removal of `user_mang.models.visitor.Visitor` | imports `Visitor`, which no longer exists -> `ImportError` at collection time |
| `chat_api_test_views_comprehensive.py` | the removal of `user_mang.models.visitor.Visitor` | imports `Visitor`, which no longer exists -> `ImportError` at collection time |
| `user_mang_test_views_comprehensive.py` | the `UnifiedSyncView` refactor | references `UserDetailView`, `AdminUserDetailView`, and `user_mang.serializers.CustomeUserSerializer`, all of which were replaced by `UnifiedSyncView` and the current serializers |

## Why they were not simply deleted

They encode real intent (ownership checks, admin user-detail behavior, field
validation) that is still valuable — it just needs to be re-expressed against
the current views/serializers rather than thrown away outright.

## What "re-enabling" requires

Before any of these files can move back into `auth_api/`, `chat_api/`, or
`user_mang/` and be collected again, they must be rewritten to:

1. Drop all references to `user_mang.models.visitor.Visitor` (removed model).
2. Drop all references to `UserDetailView` / `AdminUserDetailView` /
   `CustomeUserSerializer` (removed) and instead exercise the current
   `UnifiedSyncView` (see `user_mang/views.py`) and the current serializers in
   `user_mang/serializers.py`.
3. Follow the pattern already established in
   `user_mang/test_unified_sync_security.py`, which is the current,
   passing reference test suite for this surface (real endpoint via
   `reverse("user-detail")`, no mocking of removed internals).
4. Be moved back into their owning app directory (not left here) once
   rewritten, so they are picked up by normal pytest collection again.

Until that rewrite happens, treat this directory as read-only reference
material, not an active test suite.
