# Generated by Django 4.2.2 on 2023-06-29 18:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('student', '0011_collegeentrancetest'),
    ]

    operations = [
        migrations.AlterField(
            model_name='collegeentrancetest',
            name='report_of_rating',
            field=models.ImageField(null=True, upload_to='cet_reports/'),
        ),
    ]
