# Generated by Django 4.2.7 on 2025-06-28 04:38

from django.conf import settings
import django.contrib.auth.models
import django.contrib.auth.validators
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='CustomUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('username', models.CharField(error_messages={'unique': 'A user with that username already exists.'}, help_text='Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.', max_length=150, unique=True, validators=[django.contrib.auth.validators.UnicodeUsernameValidator()], verbose_name='username')),
                ('first_name', models.CharField(blank=True, max_length=150, verbose_name='first name')),
                ('last_name', models.CharField(blank=True, max_length=150, verbose_name='last name')),
                ('email', models.EmailField(blank=True, max_length=254, verbose_name='email address')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('role', models.CharField(choices=[('admin', 'Admin'), ('doctor', 'Doctor'), ('patient', 'Patient')], default='patient', max_length=10)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='customuser_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='customuser_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': 'Custom User',
                'verbose_name_plural': 'Custom Users',
            },
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name='Device',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('device_type', models.CharField(max_length=100)),
                ('serial_number', models.CharField(max_length=100, unique=True)),
                ('registration_date', models.DateTimeField(auto_now_add=True)),
                ('last_data_sync', models.DateTimeField(blank=True, null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('firmware_version', models.CharField(blank=True, max_length=50, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='DoctorProfile',
            fields=[
                ('user', models.OneToOneField(limit_choices_to={'role': 'doctor'}, on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to=settings.AUTH_USER_MODEL)),
                ('specialty', models.CharField(blank=True, max_length=100, null=True)),
                ('clinic_address', models.TextField(blank=True, null=True)),
                ('contact_number', models.CharField(blank=True, max_length=20, null=True)),
                ('bio', models.TextField(blank=True, null=True)),
                ('profile_picture_url', models.URLField(blank=True, default='https://placehold.co/40x40/f0f4f7/556080?text=JD', null=True)),
                ('languages_spoken', models.JSONField(blank=True, default=list)),
                ('clinic_facilities', models.JSONField(blank=True, default=list)),
                ('theme_preference', models.CharField(default='light', max_length=50)),
                ('notification_enabled', models.BooleanField(default=True)),
                ('date_format', models.CharField(default='YYYY-MM-DD', max_length=20)),
                ('time_format', models.CharField(default='HH:MM', max_length=20)),
                ('default_report_template', models.TextField(blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='PatientProfile',
            fields=[
                ('user', models.OneToOneField(limit_choices_to={'role': 'patient'}, on_delete=django.db.models.deletion.CASCADE, primary_key=True, serialize=False, to=settings.AUTH_USER_MODEL)),
                ('date_of_birth', models.DateField(blank=True, null=True)),
                ('gender', models.CharField(blank=True, choices=[('male', 'Male'), ('female', 'Female'), ('other', 'Other')], max_length=10, null=True)),
                ('blood_group', models.CharField(blank=True, max_length=5, null=True)),
                ('contact_number', models.CharField(blank=True, max_length=20, null=True)),
                ('address', models.TextField(blank=True, null=True)),
                ('medical_history', models.TextField(blank=True, null=True)),
                ('emergency_contact_name', models.CharField(blank=True, max_length=100, null=True)),
                ('emergency_contact_relationship', models.CharField(blank=True, max_length=50, null=True)),
                ('emergency_contact_phone', models.CharField(blank=True, max_length=20, null=True)),
                ('profile_picture_url', models.URLField(blank=True, default='https://placehold.co/40x40/f0f4f7/556080?text=PJ', null=True)),
                ('notification_enabled', models.BooleanField(default=True)),
                ('preferred_language', models.CharField(default='en', max_length=10)),
            ],
        ),
        migrations.CreateModel(
            name='SystemNotification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('message', models.TextField()),
                ('notification_type', models.CharField(choices=[('info', 'Information'), ('warning', 'Warning'), ('success', 'Success'), ('error', 'Error')], default='info', max_length=100)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('is_read', models.BooleanField(default=False)),
                ('recipient', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='notifications', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-timestamp'],
            },
        ),
        migrations.CreateModel(
            name='Message',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('subject', models.CharField(max_length=255)),
                ('body', models.TextField()),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('is_read', models.BooleanField(default=False)),
                ('receiver', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='received_messages', to=settings.AUTH_USER_MODEL)),
                ('sender', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sent_messages', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-timestamp'],
            },
        ),
        migrations.CreateModel(
            name='VitalSign',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(default=django.utils.timezone.now)),
                ('vital_type', models.CharField(choices=[('heart_rate', 'Heart Rate'), ('blood_pressure', 'Blood Pressure'), ('temperature', 'Temperature'), ('oxygen_saturation', 'Oxygen Saturation'), ('glucose_level', 'Glucose Level')], max_length=50)),
                ('value', models.FloatField()),
                ('unit', models.CharField(blank=True, max_length=20, null=True)),
                ('status', models.CharField(blank=True, max_length=50, null=True)),
                ('recorded_by_device', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='medidash.device')),
                ('patient', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='vitals', to='medidash.patientprofile')),
            ],
            options={
                'ordering': ['-timestamp'],
            },
        ),
        migrations.CreateModel(
            name='Report',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('report_date', models.DateField(default=django.utils.timezone.now)),
                ('title', models.CharField(default='Patient Report', max_length=255)),
                ('chief_complaint', models.TextField(blank=True, null=True)),
                ('diagnosis', models.TextField(blank=True, null=True)),
                ('treatment_plan', models.TextField(blank=True, null=True)),
                ('follow_up_date', models.DateField(blank=True, null=True)),
                ('notes', models.TextField(blank=True, null=True)),
                ('doctor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='generated_reports', to='medidash.doctorprofile')),
                ('patient', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reports', to='medidash.patientprofile')),
            ],
            options={
                'ordering': ['-report_date'],
            },
        ),
        migrations.CreateModel(
            name='MedicalRecord',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('record_type', models.CharField(choices=[('prescription', 'Prescription'), ('lab_result', 'Lab Result'), ('diagnosis', 'Diagnosis'), ('consultation_note', 'Consultation Note')], max_length=100)),
                ('record_date', models.DateField(default=django.utils.timezone.now)),
                ('title', models.CharField(max_length=255)),
                ('description', models.TextField(blank=True, null=True)),
                ('document', models.FileField(blank=True, null=True, upload_to='medical_records/')),
                ('doctor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_records', to='medidash.doctorprofile')),
                ('patient', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='medical_records', to='medidash.patientprofile')),
            ],
            options={
                'ordering': ['-record_date'],
            },
        ),
        migrations.AddField(
            model_name='device',
            name='patient',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='devices', to='medidash.patientprofile'),
        ),
        migrations.CreateModel(
            name='Alert',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('alert_type', models.CharField(choices=[('critical_vital', 'Critical Vital'), ('device_malfunction', 'Device Malfunction'), ('medication_reminder', 'Medication Reminder'), ('appointment_reminder', 'Appointment Reminder'), ('system_error', 'System Error')], max_length=100)),
                ('message', models.TextField()),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('acknowledged', 'Acknowledged'), ('dismissed', 'Dismissed')], default='pending', max_length=50)),
                ('severity', models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')], default='medium', max_length=20)),
                ('assigned_to', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='assigned_alerts', to=settings.AUTH_USER_MODEL)),
                ('device', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='alerts', to='medidash.device')),
                ('patient', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='alerts', to='medidash.patientprofile')),
            ],
            options={
                'ordering': ['-timestamp'],
            },
        ),
    ]
