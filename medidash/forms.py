from django import forms
from django.contrib.auth.forms import UserCreationForm # For initial user creation in registration
from django.core.exceptions import ValidationError
from .models import (
    CustomUser, DoctorProfile, PatientProfile, # Import models for ModelForms
    GENDER_CHOICES, # <-- IMPORT GENDER_CHOICES from models.py
    SiteSettings
)

# --- User Registration Forms ---
class DoctorRegistrationForm(forms.Form):
    """
    Django Form for registering a new Doctor.
    This is a regular Form, as it creates a CustomUser and a DoctorProfile.
    """
    full_name = forms.CharField(
        label="Full Name",
        max_length=100,
        widget=forms.TextInput(attrs={'placeholder': 'Enter name'})
    )
    email = forms.EmailField(
        label="Email Address",
        widget=forms.EmailInput(attrs={'placeholder': 'Enter email'})
    )
    # New Password Fields
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={'placeholder': 'Enter password'})
    )
    password_confirm = forms.CharField(
        label="Confirm Password",
        widget=forms.PasswordInput(attrs={'placeholder': 'Confirm password'})
    )
    # End New Password Fields
    
    license_number = forms.CharField(
        label="Registration Number",
        max_length=50,
        widget=forms.TextInput(attrs={'placeholder': 'Doctor registration no'})
    )
    SPECIALTY_CHOICES = [
        ('', 'Select Specialty'), # Default empty choice
        ('neurology', 'Neurology'),
        ('cardiology', 'Cardiology'),
        ('dermatology', 'Dermatology'),
        ('pediatrics', 'Pediatrics'),
        ('orthopedics', 'Orthopedics'),
    ]
    specialty = forms.ChoiceField(
        label="Specialty",
        choices=SPECIALTY_CHOICES,
        widget=forms.Select(attrs={'class': 'custom-select'})
    )
    dob = forms.DateField(
        label="Date of Birth",
        widget=forms.DateInput(attrs={'type': 'date'})
    )
    phone = forms.CharField(
        label="Phone Number",
        max_length=15,
        widget=forms.TextInput(attrs={'placeholder': 'Enter Phone Number'})
    )
    gender = forms.ChoiceField(
        label="Gender",
        choices=GENDER_CHOICES,
        widget=forms.Select(attrs={'class': 'custom-select'})
    )
    bio = forms.CharField(
        label="Bio / Description",
        widget=forms.Textarea(attrs={'rows': 4, 'placeholder': 'Brief description about the doctor...'}),
        required=False
    )
    profile_pic = forms.ImageField(
        label="Profile Picture",
        required=False
    )

    def clean_email(self):
        """
        Validate that the email address is not already in use by another user.
        """
        email = self.cleaned_data['email']
        if CustomUser.objects.filter(email=email).exists():
            raise ValidationError("This email address is already registered.")
        return email

    def clean(self):
        """
        Custom cleaning method to validate password and password_confirm match.
        """
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')

        if password and password_confirm and password != password_confirm:
            self.add_error('password_confirm', "Passwords do not match.")
        return cleaned_data


class PatientRegistrationForm(forms.Form):
    """
    Django Form for registering a new Patient.
    This is a regular Form, as it creates a CustomUser and a PatientProfile.
    """
    full_name = forms.CharField(
        label="Full Name",
        max_length=100,
        widget=forms.TextInput(attrs={'placeholder': 'Patient Full Name'})
    )
    email = forms.EmailField(
        label="Email Address",
        widget=forms.EmailInput(attrs={'placeholder': 'patient@example.com'})
    )
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={'placeholder': 'Enter password'})
    )
    password_confirm = forms.CharField(
        label="Confirm Password",
        widget=forms.PasswordInput(attrs={'placeholder': 'Confirm password'})
    )

    doctor = forms.ModelChoiceField(
        queryset=DoctorProfile.objects.all(),
        required=True,
        label="Select Doctor",
        widget=forms.Select(attrs={'class': 'custom-select', 'data-live-search': 'true'})
    )

    BLOOD_GROUP_CHOICES = [
        ('', 'Select Blood Group'), ('A+', 'A+'), ('B+', 'B+'), ('AB+', 'AB+'),
        ('O+', 'O+'), ('A-', 'A-'), ('B-', 'B-'), ('AB-', 'AB-'), ('O-', 'O-'),
    ]
    blood_group = forms.ChoiceField(
        label="Blood Group",
        choices=BLOOD_GROUP_CHOICES,
        widget=forms.Select(attrs={'class': 'custom-select'})
    )
    dob = forms.DateField(
        label="Date of Birth",
        widget=forms.DateInput(attrs={'type': 'date'})
    )
    phone = forms.CharField(
        label="Phone Number",
        max_length=15,
        widget=forms.TextInput(attrs={'placeholder': '+1 234 567 8900'})
    )
    gender = forms.ChoiceField(
        label='Gender',
        choices=GENDER_CHOICES,
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    medical_conditions = forms.CharField(
        label="Existing Medical Conditions",
        required=False,
        widget=forms.Textarea(attrs={'rows': 3, 'placeholder': 'e.g., Diabetes, Hypertension'})
    )
    profile_pic = forms.ImageField(
        label="Profile Picture",
        required=False
    )

    emergency_name = forms.CharField(
        label="Emergency Contact Name",
        max_length=100,
        widget=forms.TextInput(attrs={'placeholder': 'Jane Doe'})
    )
    emergency_phone = forms.CharField(
        label="Emergency Contact Phone",
        max_length=15,
        widget=forms.TextInput(attrs={'placeholder': 'Emergency Phone'})
    )
    relationship = forms.CharField(
        label="Relationship to Patient",
        max_length=50,
        widget=forms.TextInput(attrs={'placeholder': 'e.g., Parent, Spouse'})
    )

    def clean_email(self):
        """
        Validate that the email address is not already in use by another user.
        """
        email = self.cleaned_data['email']
        if CustomUser.objects.filter(email=email).exists():
            raise ValidationError("This email address is already registered.")
        return email

    def clean(self):
        """
        Custom cleaning method to validate password and password_confirm match.
        """
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')

        if password and password_confirm and password != password_confirm:
            self.add_error('password_confirm', "Passwords do not match.")
        return cleaned_data

# --- Device Registration Form ---
class DeviceRegistrationForm(forms.Form):
    """
    Django Form for registering a new Medical Device.
    """
    device_name = forms.CharField(
        label="Device Name",
        max_length=100,
        widget=forms.TextInput(attrs={'placeholder': 'e.g., Blood Pressure Monitor'})
    )
    mac_address = forms.CharField(
        label="MAC Address",
        max_length=17,
        widget=forms.TextInput(attrs={'placeholder': 'e.g., 00:1A:2B:3C:4D:5E',
                                       'pattern': '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',
                                       'title': 'Enter a valid MAC address (e.g., 00:1A:2B:3C:4D:5E)'})
    )
    # This field maps to PatientProfile.pk for assignment
    assigned_patient_id = forms.IntegerField(
        label="Assigned Patient ID",
        required=False,
        widget=forms.NumberInput(attrs={'placeholder': 'Optional: Assign to Patient User ID'})
    )
    device_location = forms.CharField(
        label="Location",
        max_length=255,
        required=False,
        widget=forms.TextInput(attrs={'placeholder': 'e.g., Room 101, Lab A'})
    )
    device_description = forms.CharField(
        label="Description",
        widget=forms.Textarea(attrs={'rows': 4, 'placeholder': 'Brief description of the device and its purpose...'}),
        required=False
    )

# --- Settings Forms (for admin/doctor/patient general profile update) ---
class UserProfileForm(forms.Form):
    """
    Generic Django Form for editing a user's core profile information (name, email, profile pic).
    Used in settings_view for all roles.
    """
    full_name = forms.CharField(label="Full Name", max_length=100)
    middle_name = forms.CharField(label="Middle Name", max_length=50, required=False)
    email = forms.EmailField(label="Email Address")
    profile_pic = forms.ImageField(label="Profile Picture", required=False)

class SecurityForm(forms.Form):
    """
    Django Form for handling password changes and 2FA settings.
    """
    current_password = forms.CharField(
        label="Current Password",
        max_length=100,
        widget=forms.PasswordInput(attrs={'placeholder': '••••••••'})
    )
    new_password = forms.CharField(
        label="New Password",
        max_length=100,
        widget=forms.PasswordInput(attrs={'placeholder': '••••••••'})
    )
    two_factor_authentication = forms.BooleanField(
        label="Enable Two-Factor Authentication",
        required=False,
        widget=forms.CheckboxInput(attrs={'id': 'twoFactor'})
    )

class NotificationSettingsForm(forms.Form):
    """
    Django Form for managing user notification preferences.
    """
    email_notifications = forms.BooleanField(label="Email Notifications", required=False)
    sms_alerts = forms.BooleanField(label="SMS Alerts", required=False)
    push_notifications = forms.BooleanField(label="Push Notifications", required=False)


# --- ModelForms for updating existing DoctorProfile and PatientProfile instances ---
class DoctorUpdateForm(forms.ModelForm):
    """
    ModelForm for updating an existing DoctorProfile instance.
    Includes fields from CustomUser (via explicit fields) and DoctorProfile.
    """
    full_name = forms.CharField(label="Full Name", max_length=100)
    email = forms.EmailField(label="Email Address")
    profile_pic = forms.ImageField(label="Profile Picture", required=False)

    SPECIALTY_CHOICES = [
        ('', 'Select Specialty'),
        ('neurology', 'Neurology'),
        ('cardiology', 'Cardiology'),
        ('dermatology', 'Dermatology'),
        ('pediatrics', 'Pediatrics'),
        ('orthopedics', 'Orthopedics'),
        # Add more as needed
    ]
    THEME_CHOICES = [
        ('light', 'Light'),
        ('dark', 'Dark'),
    ]
    DATE_FORMAT_CHOICES = [
        ('YYYY-MM-DD', 'YYYY-MM-DD (2024-01-31)'),
        ('DD-MM-YYYY', 'DD-MM-YYYY (31-01-2024)'),
        ('MM/DD/YYYY', 'MM/DD/YYYY (01/31/2024)'),
    ]
    TIME_FORMAT_CHOICES = [
        ('HH:MM', 'HH:MM (24-hour)'),
        ('hh:mm A', 'hh:mm A (12-hour)'),
    ]

    specialty = forms.ChoiceField(label="Specialty", choices=SPECIALTY_CHOICES, required=False)
    theme_preference = forms.ChoiceField(label="Theme preference", choices=THEME_CHOICES, required=False)
    date_format = forms.ChoiceField(label="Date format", choices=DATE_FORMAT_CHOICES, required=False)
    time_format = forms.ChoiceField(label="Time format", choices=TIME_FORMAT_CHOICES, required=False)

    class Meta:
        model = DoctorProfile
        fields = [
            'specialty', 'clinic_address', 'contact_number', 'bio', 'profile_picture',
            'email_notifications_enabled', 'sms_notifications_enabled', 'push_notifications_enabled',
            'two_factor_authentication_enabled',
            'languages_spoken', 'clinic_facilities', 'theme_preference', 'date_format',
            'time_format', 'default_report_template'
        ]
        widgets = {
            'profile_picture': forms.ClearableFileInput(),
            'languages_spoken': forms.TextInput(attrs={'placeholder': 'e.g., ["English", "Spanish"]'}),
            'clinic_facilities': forms.TextInput(attrs={'placeholder': 'e.g., ["Wheelchair Access", "Lab On-site"]'}),
            'specialty': forms.Select(),
            'theme_preference': forms.Select(),
            'date_format': forms.Select(),
            'time_format': forms.Select(),
        }

    def __init__(self, *args, **kwargs): # Corrected __init__ method name
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.user:
            self.fields['full_name'].initial = self.instance.user.get_full_name()
            self.fields['email'].initial = self.instance.user.email
            self.fields['profile_pic'].initial = self.instance.profile_picture # For initial display

        # Ensure JSONField widgets are text inputs
        self.fields['languages_spoken'].widget = forms.TextInput(attrs={'placeholder': 'e.g., ["English", "Spanish"]'})
        self.fields['clinic_facilities'].widget = forms.TextInput(attrs={'placeholder': 'e.g., ["Wheelchair Access", "Lab On-site"]'})


    def save(self, commit=True):
        doctor_profile = super().save(commit=False)
        user = doctor_profile.user
        
        # Update CustomUser fields
        full_name = self.cleaned_data['full_name']
        user.first_name = full_name.split(' ')[0] if ' ' in full_name else full_name
        user.last_name = full_name.split(' ')[-1] if ' ' in full_name else ''
        user.email = self.cleaned_data['email']
        user.save()

        # Handle profile picture separately if needed (already handled by ModelForm save for ImageField)
        if 'profile_pic' in self.cleaned_data and self.cleaned_data['profile_pic']:
            doctor_profile.profile_picture = self.cleaned_data['profile_pic']

        if commit:
            doctor_profile.save()
        return doctor_profile


class PatientUpdateForm(forms.ModelForm):
    """
    ModelForm for updating an existing PatientProfile instance.
    Includes fields from CustomUser (via explicit fields) and PatientProfile.
    """
    full_name = forms.CharField(label="Full Name", max_length=100)
    email = forms.EmailField(label="Email Address")
    profile_pic = forms.ImageField(label="Profile Picture", required=False)

    class Meta:
        model = PatientProfile
        fields = [
            'date_of_birth', 'gender', 'blood_group', 'contact_number', 'address',
            'medical_history', 'emergency_contact_name', 'emergency_contact_relationship',
            'emergency_contact_phone', 'profile_picture', # Corrected 'profile_picture'
            'email_notifications_enabled', 'sms_notifications_enabled', 'push_notifications_enabled', # These fields are now in the model
            'preferred_language'
        ]
        widgets = {
            'profile_picture': forms.ClearableFileInput(),
            'date_of_birth': forms.DateInput(attrs={'type': 'date'}),
        }

    def __init__(self, *args, **kwargs): # Corrected __init__ method name
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.user:
            self.fields['full_name'].initial = self.instance.user.get_full_name()
            self.fields['email'].initial = self.instance.user.email
            self.fields['profile_pic'].initial = self.instance.profile_picture # For initial display

    def save(self, commit=True):
        patient_profile = super().save(commit=False)
        user = patient_profile.user
        
        # Update CustomUser fields
        full_name = self.cleaned_data['full_name']
        user.first_name = full_name.split(' ')[0] if ' ' in full_name else full_name
        user.last_name = full_name.split(' ')[-1] if ' ' in full_name else ''
        user.email = self.cleaned_data['email']
        user.save()

        # Handle profile picture separately if needed (already handled by ModelForm save for ImageField)
        if 'profile_pic' in self.cleaned_data and self.cleaned_data['profile_pic']:
            patient_profile.profile_picture = self.cleaned_data['profile_pic']

        if commit:
            patient_profile.save()
        return patient_profile

class SiteSettingsForm(forms.ModelForm):
    class Meta:
        model = SiteSettings
        fields = ['site_name', 'date_format', 'time_format']
        widgets = {
            'site_name': forms.TextInput(attrs={'class': 'form-control', 'required': True}),
            'date_format': forms.Select(choices=[('YYYY-MM-DD', 'YYYY-MM-DD (2024-01-31)'), ('DD-MM-YYYY', 'DD-MM-YYYY (31-01-2024)'), ('MM/DD/YYYY', 'MM/DD/YYYY (01/31/2024)')]),
            'time_format': forms.Select(choices=[('HH:MM', 'HH:MM (24-hour)'), ('hh:mm A', 'hh:mm A (12-hour)')]),
        }

# Update NotificationSettingsForm for admin
class AdminNotificationSettingsForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['email_notifications_enabled', 'sms_notifications_enabled', 'two_factor_authentication_enabled']
        widgets = {
            'email_notifications_enabled': forms.CheckboxInput(),
            'sms_notifications_enabled': forms.CheckboxInput(),
            'two_factor_authentication_enabled': forms.CheckboxInput(),
        }
