# Generated by Django 4.2.2 on 2023-07-10 11:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('student', '0025_alter_interviewlogs_processed_by'),
    ]

    operations = [
        migrations.AlterField(
            model_name='interviewlogs',
            name='status',
            field=models.CharField(default='okay', max_length=255),
        ),
    ]