# Generated by Django 2.2 on 2022-05-11 19:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('solisticaAPI', '0015_auto_20220511_1900'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='historial',
            name='idantena',
        ),
        migrations.RemoveField(
            model_name='validaciones',
            name='idantena',
        ),
        migrations.AddField(
            model_name='historial',
            name='antena',
            field=models.SlugField(default='Desconocido'),
        ),
        migrations.AddField(
            model_name='validaciones',
            name='antena',
            field=models.SlugField(default='Desconocido'),
        ),
        migrations.AlterField(
            model_name='historial',
            name='epc',
            field=models.SlugField(),
        ),
        migrations.AlterField(
            model_name='historial',
            name='estado',
            field=models.SlugField(max_length=15),
        ),
        migrations.AlterField(
            model_name='historial',
            name='lugar',
            field=models.SlugField(default='Desconocido', max_length=30),
        ),
        migrations.AlterField(
            model_name='historial',
            name='movimiento',
            field=models.SlugField(max_length=20),
        ),
        migrations.AlterField(
            model_name='historial',
            name='tipo',
            field=models.SlugField(max_length=20),
        ),
        migrations.AlterField(
            model_name='historial',
            name='usuario',
            field=models.SlugField(default='Desconocido', max_length=30),
        ),
        migrations.AlterField(
            model_name='neumatico',
            name='epc',
            field=models.SlugField(),
        ),
        migrations.AlterField(
            model_name='neumatico',
            name='idP',
            field=models.SlugField(max_length=20),
        ),
        migrations.AlterField(
            model_name='neumatico',
            name='pos',
            field=models.SlugField(max_length=10),
        ),
        migrations.AlterField(
            model_name='neumatico',
            name='trailer',
            field=models.SlugField(),
        ),
        migrations.AlterField(
            model_name='stripecustomer',
            name='id_stripe',
            field=models.SlugField(),
        ),
        migrations.AlterField(
            model_name='stripecustomer',
            name='usuario',
            field=models.SlugField(),
        ),
        migrations.AlterField(
            model_name='validaciones',
            name='coordenadas',
            field=models.SlugField(default='19.82976,-98.97317'),
        ),
        migrations.AlterField(
            model_name='validaciones',
            name='epc',
            field=models.SlugField(),
        ),
        migrations.AlterField(
            model_name='validaciones',
            name='lector',
            field=models.SlugField(default='Desconocido', max_length=20),
        ),
        migrations.AlterField(
            model_name='vehiculo',
            name='epc',
            field=models.SlugField(),
        ),
        migrations.AlterField(
            model_name='vehiculo',
            name='layout',
            field=models.SlugField(max_length=25),
        ),
        migrations.AlterField(
            model_name='vehiculo',
            name='placa',
            field=models.SlugField(),
        ),
        migrations.AlterField(
            model_name='vehiculo',
            name='tipo',
            field=models.SlugField(max_length=15),
        ),
    ]