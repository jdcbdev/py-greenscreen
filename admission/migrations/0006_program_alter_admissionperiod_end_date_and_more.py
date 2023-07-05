# Generated by Django 4.2.2 on 2023-07-05 06:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('admission', '0005_admissionperiod_concat_date_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Program',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('code', models.CharField(default='', max_length=255, unique=True)),
                ('name', models.CharField(default='', max_length=255)),
            ],
        ),
        migrations.AlterField(
            model_name='admissionperiod',
            name='end_date',
            field=models.DateField(null=True),
        ),
        migrations.AlterField(
            model_name='admissionperiod',
            name='start_date',
            field=models.DateField(null=True),
        ),
    ]
