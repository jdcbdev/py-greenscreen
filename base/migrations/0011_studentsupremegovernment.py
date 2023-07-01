# Generated by Django 4.2.2 on 2023-07-01 03:44

from django.db import migrations, models

def load_initial_data(apps, schema_editor):
    Position = apps.get_model('base', 'StudentSupremeGovernment')

    positions = [
        'President',
        'Vice President (Internal/External)',
        'Secretary',
        'Treasurer',
        'Auditor',
        'Project Manager',
        'P.I.O. (Public Information Officer)',
        'SGT. At Arms',
        'Grade Level Representative',
        'Volunteer',
        'None',
    ]

    for position_name in positions:
        position = Position(name=position_name)
        position.save()

class Migration(migrations.Migration):

    dependencies = [
        ('base', '0010_classroomorganization'),
    ]

    operations = [
        migrations.CreateModel(
            name='StudentSupremeGovernment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
            ],
        ),
        migrations.RunPython(load_initial_data),
    ]
