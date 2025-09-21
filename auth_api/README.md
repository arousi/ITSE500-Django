# auth_api

English
- Purpose: Authentication and OAuth (Google, OpenRouter, GitHub, Microsoft). Issues JWTs for API access.
- Key endpoints: /api/v1/auth_api/login/, /reg/, /logout/, /verify-email-pin/, /set-password-after-email-verify/, provider /authorize/ and /callback/.
- Notes: Protected endpoints expect Authorization: Bearer <access>. Some flows accept refresh tokens for bridging.

العربية
- الهدف: المصادقة وتكامل OAuth (جوجل، OpenRouter، GitHub، Microsoft). يصدر JWT للوصول إلى الواجهات.
- أهم النقاط: /api/v1/auth_api/login/، /reg/، /logout/، /verify-email-pin/، /set-password-after-email-verify/، ومسارات /authorize/ و /callback/.
- ملاحظات: استخدم الهيدر Authorization: Bearer <access> للنقاط المحمية.
