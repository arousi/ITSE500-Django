import logging

# إنشاء logger جديد
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# إضافة Handler للطباعة في الـ console
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# تحديد صيغة الرسائل
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)

# ربط الـ handler بالـ logger
if not logger.handlers:
    logger.addHandler(console_handler)
