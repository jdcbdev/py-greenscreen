# Generated by Django 4.2.2 on 2023-07-05 11:10

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('admission', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Quota',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('number', models.IntegerField(default=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('program', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='admission.program')),
                ('school_year', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='admission.schoolyear')),
            ],
        ),
    ]
