# Generated by Django 4.2.2 on 2023-07-14 09:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('student', '0027_interviewlogs_score'),
    ]

    operations = [
        migrations.AddField(
            model_name='admissionapplication',
            name='total',
            field=models.FloatField(null=True),
        ),
    ]
