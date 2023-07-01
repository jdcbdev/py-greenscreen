# Generated by Django 4.2.2 on 2023-06-29 15:26

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('student', '0010_student_profile_photo_delete_uploadedphoto'),
    ]

    operations = [
        migrations.CreateModel(
            name='CollegeEntranceTest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('application_number', models.CharField(max_length=100, unique=True)),
                ('rating_period', models.CharField(max_length=100)),
                ('overall_percentile_rank', models.DecimalField(decimal_places=2, max_digits=5)),
                ('english_proficiency_skills', models.DecimalField(decimal_places=2, max_digits=5)),
                ('reading_comprehension_skills', models.DecimalField(decimal_places=2, max_digits=5)),
                ('science_process_skills', models.DecimalField(decimal_places=2, max_digits=5)),
                ('quantitative_skills', models.DecimalField(decimal_places=2, max_digits=5)),
                ('abstract_thinking_skills', models.DecimalField(decimal_places=2, max_digits=5)),
                ('report_of_rating', models.ImageField(upload_to='cet_reports/')),
                ('student', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='student.student')),
            ],
        ),
    ]