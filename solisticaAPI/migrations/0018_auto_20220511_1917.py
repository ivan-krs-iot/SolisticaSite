# Generated by Django 2.2 on 2022-05-11 19:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('solisticaAPI', '0017_auto_20220511_1916'),
    ]

    operations = [
        migrations.AlterField(
            model_name='historial',
            name='antena',
            field=models.SlugField(default='1'),
        ),
        migrations.AlterField(
            model_name='validaciones',
            name='antena',
            field=models.SlugField(default='1'),
        ),
        migrations.AlterField(
            model_name='validaciones',
            name='coordenadas',
            field=models.SlugField(default='19'),
        ),
    ]
