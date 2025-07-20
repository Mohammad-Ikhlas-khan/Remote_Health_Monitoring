# medidash/models.py

from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.utils import timezone
import uuid
from django.conf import settings

class CustomUser(AbstractUser):
    """
    Custom User model to extend Django's default User, adding a 'role' field
    to distinguish between Admin, Doctor, and Patient.
    """
    USER_ROLES = (
        ('admin', 'Admin'),
        ('doctor', 'Doctor'),
        ('patient', 'Patient'),
    )
    role = models.CharField(max_length=10, choices=USER_ROLES)

    # Add related_name to avoid clashes with default User model's groups and user_permissions
    groups = models.ManyToManyField(
        Group,
        verbose_name=('groups'),
        blank=True,
        help_text=(
            'The groups this user belongs to. A user will get all permissions '
            'granted to each of their groups.'
        ),
        related_name="customuser_set", # Changed related_name
        related_query_name="user",
    )
    user_permissions = models.ManyToManyField(
        Permission,
        verbose_name=('user permissions'),
        blank=True,
        help_text=('Specific permissions for this user.'),
        related_name="customuser_set", # Changed related_name
        related_query_name="user",
    )

    # Add to CustomUser for admin notification preferences and 2FA
    email_notifications_enabled = models.BooleanField(default=True)
    sms_notifications_enabled = models.BooleanField(default=False)
    two_factor_authentication_enabled = models.BooleanField(default=False)

    middle_name = models.CharField(max_length=50, blank=True, null=True)

    def __str__(self):
        return f"{self.username} ({self.role})"

    class Meta:
        verbose_name = 'Custom User'
        verbose_name_plural = 'Custom Users'

# Define GENDER_CHOICES at the module level for use in models and forms
GENDER_CHOICES = [
    ('male', 'Male'),
    ('female', 'Female'),
    ('other', 'Other'),
]

class DoctorProfile(models.Model):
    """
    Model to store additional information specific to a Doctor.
    """
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, primary_key=True, limit_choices_to={'role': 'doctor'})
    specialty = models.CharField(max_length=100, blank=True, null=True)
    clinic_address = models.TextField(blank=True, null=True)
    contact_number = models.CharField(max_length=20, blank=True, null=True)
    bio = models.TextField(blank=True, null=True)
    
    # Changed from URLField to ImageField
    profile_picture = models.ImageField(upload_to='profile_pics/doctors/', blank=True, null=True)
    
    # Status field for records_view
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    ]
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='active')

    # Granular notification settings to match NotificationSettingsForm
    email_notifications_enabled = models.BooleanField(default=True)
    sms_notifications_enabled = models.BooleanField(default=False)
    push_notifications_enabled = models.BooleanField(default=True)
    
    # Added for security form compatibility
    two_factor_authentication_enabled = models.BooleanField(default=False)

    # Other settings from settings_doctor.html
    languages_spoken = models.JSONField(default=list, blank=True) # Stored as JSON array
    clinic_facilities = models.JSONField(default=list, blank=True) # Stored as JSON array
    theme_preference = models.CharField(max_length=50, default='light')
    date_format = models.CharField(max_length=20, default='YYYY-MM-DD')
    time_format = models.CharField(max_length=20, default='HH:MM')
    default_report_template = models.TextField(blank=True, null=True)


    def __str__(self):
        return f"Dr. {self.user.get_full_name() or self.user.username}"

class PatientProfile(models.Model):
    """
    Model to store additional information specific to a Patient.
    """
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, primary_key=True, limit_choices_to={'role': 'patient'})
    doctor = models.ForeignKey('DoctorProfile', on_delete=models.PROTECT, related_name='patients', null=True, blank=True)
    date_of_birth = models.DateField(blank=True, null=True)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, blank=True, null=True) # Using global GENDER_CHOICES
    blood_group = models.CharField(max_length=5, blank=True, null=True)
    contact_number = models.CharField(max_length=20, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    medical_history = models.TextField(blank=True, null=True) # General medical history
    emergency_contact_name = models.CharField(max_length=100, blank=True, null=True)
    emergency_contact_relationship = models.CharField(max_length=50, blank=True, null=True)
    emergency_contact_phone = models.CharField(max_length=20, blank=True, null=True)
    
    # Changed from URLField to ImageField
    profile_picture = models.ImageField(upload_to='profile_pics/patients/', blank=True, null=True)
    
    # Status field for records_view
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    ]
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='active')

    # Granular notification settings to match NotificationSettingsForm
    email_notifications_enabled = models.BooleanField(default=True)
    sms_notifications_enabled = models.BooleanField(default=False)
    push_notifications_enabled = models.BooleanField(default=True)

    # Patient-specific settings
    preferred_language = models.CharField(max_length=10, default='en') # From profile.html

    def __str__(self):
        return f"Patient: {self.user.get_full_name() or self.user.username}"

class Device(models.Model):
    """
    Represents a health monitoring device linked to a patient.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False) # UUID for device ID
    patient = models.ForeignKey(PatientProfile, on_delete=models.SET_NULL, null=True, blank=True, related_name='devices')
    
    # Added device_name, device_location, device_description
    device_name = models.CharField(max_length=100, default='Unnamed Device')
    device_type = models.CharField(max_length=100) # e.g., 'Smartwatch', 'Blood Pressure Monitor', 'Glucometer'
    
    # Changed MAC_Address to mac_address (PEP8)
    mac_address = models.CharField(max_length=100, unique=True)
    
    device_location = models.CharField(max_length=255, blank=True, null=True)
    device_description = models.TextField(blank=True, null=True)

    registration_date = models.DateTimeField(auto_now_add=True)
    last_data_sync = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True) # Used for online/offline status in dashboard
    firmware_version = models.CharField(max_length=50, blank=True, null=True)

    def __str__(self):
        return f"Device {self.device_name} ({self.mac_address}) for {self.patient.user.username if self.patient else 'Unassigned'}"

class VitalSign(models.Model):
    """
    Records a vital sign measurement for a patient.
    """
    patient = models.ForeignKey(PatientProfile, on_delete=models.CASCADE, related_name='vitals')
    timestamp = models.DateTimeField(default=timezone.now)
    vital_type = models.CharField(max_length=50, # e.g., 'Heart Rate', 'Blood Pressure', 'Temperature', 'Oxygen Saturation'
                                  choices=[('heart_rate', 'Heart Rate'),
                                           ('blood_pressure', 'Blood Pressure'),
                                           ('temperature', 'Temperature'),
                                           ('oxygen_saturation', 'Oxygen Saturation'),
                                           ('glucose_level', 'Glucose Level')])
    value = models.FloatField()
    unit = models.CharField(max_length=20, blank=True, null=True) # e.g., 'bpm', 'mmHg', '°C', '%'
    status = models.CharField(max_length=50, blank=True, null=True) # e.g., 'Normal', 'High', 'Low'
    recorded_by_device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f"{self.patient.user.username}'s {self.vital_type} at {self.timestamp}: {self.value}{self.unit or ''}"

    class Meta:
        ordering = ['-timestamp'] # Order by most recent first

class MedicalRecord(models.Model):
    """
    Stores a patient's medical records (e.g., prescriptions, lab results, diagnoses).
    """
    patient = models.ForeignKey(PatientProfile, on_delete=models.CASCADE, related_name='medical_records')
    doctor = models.ForeignKey(DoctorProfile, on_delete=models.SET_NULL, null=True, blank=True, related_name='created_records')
    record_type = models.CharField(max_length=100, # e.g., 'Prescription', 'Lab Result', 'Diagnosis', 'Consultation Note'
                                   choices=[('prescription', 'Prescription'),
                                            ('lab_result', 'Lab Result'),
                                            ('diagnosis', 'Diagnosis'),
                                            ('consultation_note', 'Consultation Note')])
    record_date = models.DateField(default=timezone.now)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    document = models.FileField(upload_to='medical_records/', blank=True, null=True) # For PDF uploads etc.

    def __str__(self):
        return f"{self.patient.user.username}'s {self.record_type} on {self.record_date}"

    class Meta:
        ordering = ['-record_date']

class Alert(models.Model):
    """
    Represents an alert triggered by patient data or system events.
    """
    patient = models.ForeignKey(PatientProfile, on_delete=models.CASCADE, related_name='alerts', null=True, blank=True)
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True, related_name='alerts')
    alert_type = models.CharField(max_length=100, # e.g., 'Critical Vital', 'Device Malfunction', 'Appointment Reminder'
                                  choices=[('critical_vital', 'Critical Vital'),
                                           ('device_malfunction', 'Device Malfunction'),
                                           ('medication_reminder', 'Medication Reminder'),
                                           ('appointment_reminder', 'Appointment Reminder'),
                                           ('system_error', 'System Error')])
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50, default='pending',
                              choices=[('pending', 'Pending'), ('acknowledged', 'Acknowledged'), ('dismissed', 'Dismissed')])
    severity = models.CharField(max_length=20, default='medium',
                                choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')])
    assigned_to = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_alerts')

    def __str__(self):
        return f"Alert: {self.message} (Status: {self.status})"

    class Meta:
        ordering = ['-timestamp']

class Report(models.Model):
    """
    Stores comprehensive medical reports generated by doctors for patients.
    """
    patient = models.ForeignKey(PatientProfile, on_delete=models.CASCADE, related_name='reports')
    doctor = models.ForeignKey(DoctorProfile, on_delete=models.SET_NULL, null=True, blank=True, related_name='generated_reports')
    report_date = models.DateField(default=timezone.now)
    title = models.CharField(max_length=255, default='Patient Report')
    chief_complaint = models.TextField(blank=True, null=True)
    diagnosis = models.TextField(blank=True, null=True)
    treatment_plan = models.TextField(blank=True, null=True)
    follow_up_date = models.DateField(blank=True, null=True)
    notes = models.TextField(blank=True, null=True)
    # You might link specific VitalSign or MedicalRecord instances here via a ManyToManyField
    # For simplicity, we'll keep it text-based for now.

    def __str__(self):
        return f"Report for {self.patient.user.username} on {self.report_date} by Dr. {self.doctor.user.username if self.doctor else 'N/A'}"

    class Meta:
        ordering = ['-report_date']

class Message(models.Model):
    """
    Internal messaging system between users (e.g., patient-doctor).
    """
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='sent_messages', on_delete=models.CASCADE)
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, related_name='received_messages', on_delete=models.CASCADE)
    text = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    class Meta:
        ordering = ['timestamp']

    def __str__(self):
        return f"From {self.sender} to {self.recipient}: {self.text[:30]}"

class SystemNotification(models.Model):
    """
    General system notifications for any user.
    """
    recipient = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='notifications')
    message = models.TextField()
    notification_type = models.CharField(max_length=100, default='info',
                                        choices=[('info', 'Information'), ('warning', 'Warning'), ('success', 'Success'), ('error', 'Error')])
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"Notification for {self.recipient.username}: {self.message}"

    class Meta:
        ordering = ['-timestamp']

class SiteSettings(models.Model):
    site_name = models.CharField(max_length=100, default='MediDash Health Monitoring')
    date_format = models.CharField(max_length=20, default='YYYY-MM-DD')
    time_format = models.CharField(max_length=20, default='HH:MM')

    def __str__(self):
        return self.site_name
