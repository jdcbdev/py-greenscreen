# Generated by Django 4.2.2 on 2023-06-22 15:12

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('student', '0002_student_student_type_name'),
    ]

    operations = [
        migrations.CreateModel(
            name='SchoolBackground',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('last_school_attended', models.CharField(blank=True, max_length=255)),
                ('last_course_attended', models.CharField(blank=True, max_length=255)),
                ('student', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='student.student')),
            ],
        ),
    ]