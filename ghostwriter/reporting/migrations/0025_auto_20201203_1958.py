# Generated by Django 3.0.10 on 2020-12-03 19:58

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reporting', '0024_auto_20201201_1614'),
    ]

    operations = [
        migrations.RenameField(
            model_name='reportfindinglink',
            old_name='cvss',
            new_name='cvss_score',
        ),
        migrations.RemoveField(
            model_name='finding',
            name='cvss',
        ),
        migrations.AddField(
            model_name='finding',
            name='cvss_score',
            field=models.FloatField(blank=True, help_text='Calculate the cvss score', max_length=255, null=True, verbose_name='CVSS Score'),
        ),
        migrations.AddField(
            model_name='finding',
            name='cvss_vector',
            field=models.CharField(blank=True, help_text='Calculate the cvss vector', max_length=255, null=True, verbose_name='CVSS Vector'),
        ),
        migrations.AddField(
            model_name='reportfindinglink',
            name='cvss_vector',
            field=models.TextField(blank=True, help_text='Calculate the cvss vector', null=True, verbose_name='CVSS Vector'),
        ),
    ]
