# Generated migration for adding month-day fields to Person model

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('piggySQL', '0016_rename_birth_year_person_birth_date_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='person',
            name='birth_day',
            field=models.PositiveSmallIntegerField(blank=True, help_text='出生日期(1-31)', null=True),
        ),
        migrations.AddField(
            model_name='person',
            name='birth_month',
            field=models.PositiveSmallIntegerField(blank=True, help_text='出生月份(1-12)', null=True),
        ),
        migrations.AddField(
            model_name='person',
            name='death_day',
            field=models.PositiveSmallIntegerField(blank=True, help_text='去世日期(1-31)', null=True),
        ),
        migrations.AddField(
            model_name='person',
            name='death_month',
            field=models.PositiveSmallIntegerField(blank=True, help_text='去世月份(1-12)', null=True),
        ),
    ]