# Generated by Django 2.2 on 2022-05-11 19:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('solisticaAPI', '0014_auto_20220511_1857'),
    ]

    operations = [
        migrations.AlterField(
            model_name='validaciones',
            name='coordenadas',
            field=models.CharField(max_length=50),
        ),
        migrations.AlterField(
            model_name='vehiculo',
            name='placa',
            field=models.CharField(max_length=50),
        ),
    ]
