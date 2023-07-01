# Generated by Django 4.2.2 on 2023-07-01 02:56

from django.db import migrations, models

def load_initial_data(apps, schema_editor):
    SHSStrand = apps.get_model('base', 'SHSStrand')

    strands = [
        {'code': 'ABM', 'name': 'Accountancy, Business, and Management'},
        {'code': 'GAS', 'name': 'General Academic'},
        {'code': 'HUMSS', 'name': 'Humanities and Social Sciences'},
        {'code': 'STEM', 'name': 'Science, Technology, Engineering, and Mathematics'},
        {'code': 'Agri-Fishery', 'name': 'Agri-Fishery Arts'},
        {'code': 'HomeEcon', 'name': 'Home Economics'},
        {'code': 'IndArts', 'name': 'Industrial Arts'},
        {'code': 'ICT', 'name': 'Information and Communications Technology'},
        {'code': 'Sports', 'name': 'Sports'},
        {'code': 'ArtsDesign', 'name': 'Arts and Design'},
    ]

    for strand_data in strands:
        strand = SHSStrand(code=strand_data['code'], name=strand_data['name'])
        strand.save()

class Migration(migrations.Migration):

    dependencies = [
        ('base', '0008_customapi'),
    ]

    operations = [
        migrations.CreateModel(
            name='SHSStrand',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code', models.CharField(max_length=50, unique=True)),
                ('name', models.CharField(max_length=100)),
            ],
        ),
        migrations.RunPython(load_initial_data),
    ]