# Generated by Django 4.2.2 on 2023-07-16 05:16

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('admission', '0011_alter_interviewslot_interview_time'),
    ]

    operations = [
        migrations.AddField(
            model_name='admissionperiod',
            name='program',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='admission.program'),
        ),
    ]
