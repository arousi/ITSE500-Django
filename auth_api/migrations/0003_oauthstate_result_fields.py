from django.db import migrations, models

class Migration(migrations.Migration):
    dependencies = [
        ('auth_api', '0002_oauthstate_mobile_redirect'),
    ]

    operations = [
        migrations.AddField(
            model_name='oauthstate',
            name='result_payload',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='oauthstate',
            name='result_retrieved',
            field=models.BooleanField(default=False),
        ),
    ]
