# Generated by Django 4.2.2 on 2023-07-10 12:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('student', '0026_alter_interviewlogs_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='interviewlogs',
            name='score',
            field=models.FloatField(null=True),
        ),
    ]