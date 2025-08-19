from django.db import migrations, models

class Migration(migrations.Migration):
    dependencies = [
        ('auth_api', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='oauthstate',
            name='mobile_redirect',
            field=models.CharField(max_length=512, blank=True, null=True),
        ),
    ]
