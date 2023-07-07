# Generated by Django 4.2.2 on 2023-07-07 16:09

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('admission', '0005_academicrank_admissionrole_department'),
    ]

    operations = [
        migrations.AlterField(
            model_name='academicrank',
            name='name',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name='admissionrole',
            name='name',
            field=models.CharField(max_length=255),
        ),
        migrations.AlterField(
            model_name='department',
            name='name',
            field=models.CharField(max_length=255),
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_name', models.CharField(max_length=255)),
                ('last_name', models.CharField(max_length=255)),
                ('email', models.EmailField(max_length=254)),
                ('academic_rank', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='admission.academicrank')),
                ('admission_role', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='admission.admissionrole')),
                ('department', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='admission.department')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
