# Generated by Django 4.2.2 on 2023-07-18 04:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('admission', '0012_admissionperiod_program'),
    ]

    operations = [
        migrations.AddField(
            model_name='program',
            name='department_name',
            field=models.CharField(max_length=255, null=True),
        ),
    ]
