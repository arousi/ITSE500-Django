# crypto_api

English

- Purpose: User key material (UMK) provisioning APIs.
- Endpoint: GET/POST /api/v1/crypto_api/umk/ to fetch or create a base64 32-byte key.
- Notes: POST rejects if UMK exists (rotate=true not implemented yet).

العربية

- الهدف: واجهات تهيئة مفاتيح المستخدم (UMK).
- نقطة: GET/POST /api/v1/crypto_api/umk/ للحصول أو إنشاء مفتاح base64 بطول 32 بايت.
- ملاحظة: POST ترفض إذا كان هناك مفتاح موجود (الدوران غير مدعوم حاليًا).
