# Generated by Django 2.2 on 2022-04-13 04:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('solisticaAPI', '0005_remove_neumatico_test'),
    ]

    operations = [
        migrations.CreateModel(
            name='validacion',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('epc', models.CharField(max_length=50)),
                ('fecha', models.DateTimeField(auto_now_add=True)),
                ('idlector', models.CharField(default='Desconocido', max_length=20)),
                ('coordenadas', models.CharField(default='Desconocido', max_length=60)),
            ],
        ),
    ]
