# Generated by Django 3.0.10 on 2020-12-17 18:53

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('reporting', '0029_auto_20201217_1846'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='Domain',
            new_name='ScopeDomain',
        ),
    ]
