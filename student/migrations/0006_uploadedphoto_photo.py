# Generated by Django 4.2.2 on 2023-06-28 14:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('student', '0005_student_is_cet_complete_student_is_economic_complete_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='uploadedphoto',
            name='photo',
            field=models.ImageField(null=True, upload_to='media'),
        ),
    ]