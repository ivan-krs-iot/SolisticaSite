# Generated by Django 2.2 on 2022-04-18 16:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('solisticaAPI', '0007_auto_20220418_1635'),
    ]

    operations = [
        migrations.AlterField(
            model_name='validacion',
            name='idlector',
            field=models.CharField(default='Desconocido', max_length=20),
        ),
    ]
