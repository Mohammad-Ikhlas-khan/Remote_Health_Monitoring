import datetime
import json
from django.urls import reverse
from django.shortcuts import get_object_or_404, redirect, render
from django.db import transaction
from django.http import JsonResponse
from django.views.decorators.http import require_POST
# from django.contrib.auth.decorators import login_required
# from .models import HealthRecord  # Assuming you have a HealthRecord model for files
# from .forms import HealthRecordUploadForm
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Sum, Q # Q for complex lookups in records
from django.contrib import messages
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.conf import settings # Import settings to access EMAIL_HOST_USER
from django.utils import timezone # For accurate timestamps and dates
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from collections import defaultdict

# Import your models and forms
from .models import (
    CustomUser, DoctorProfile, PatientProfile, Device, VitalSign,
    MedicalRecord, Alert, Report, Message, SystemNotification, SiteSettings
)
from .forms import (
    DoctorRegistrationForm, PatientRegistrationForm, DeviceRegistrationForm,
    UserProfileForm, SecurityForm, NotificationSettingsForm, # General settings forms
    PatientUpdateForm, DoctorUpdateForm, SiteSettingsForm, AdminNotificationSettingsForm # Specific update forms for roles
)
from .serializers import VitalSignSerializer
from .utils import send_alert_email, send_alert_sms

# --- Helper functions for role-based access (Using CustomUser's 'role' field) ---
def is_admin(user):
    """Checks if the user is authenticated and has the 'admin' role."""
    return user.is_authenticated and user.role == 'admin'

def is_doctor(user):
    """Checks if the user is authenticated and has the 'doctor' role."""
    return user.is_authenticated and user.role == 'doctor'

def is_patient(user):
    """Checks if the user is authenticated and has the 'patient' role."""
    return user.is_authenticated and user.role == 'patient'

# --- Access Denied View ---
def access_denied(request):
    """
    Displays an access denied message to authenticated users
    who try to access unauthorized pages.
    """
    return render(request, 'access_denied.html', {'message': 'You do not have permission to view this page.'})

# --- Authentication Views ---

def user_login(request):
    """
    Handles user login.
    If the user is already authenticated, redirects them based on their role.
    Otherwise, displays the login form.
    """
    if request.user.is_authenticated:
        if request.user.role == 'admin':
            return redirect('admin_dashboard')
        elif request.user.role == 'doctor':
            return redirect('doctor_dashboard')
        elif request.user.role == 'patient':
            return redirect('patient_dashboard')
        else:
            messages.warning(request, "Your account role is not recognized. Please contact support.")
            logout(request)
            return redirect('login')


    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)

        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')

            user = authenticate(request, username=username, password=password)

            if user is not None:
                login(request, user)
                messages.success(request, f"Welcome, {user.first_name or user.username}!")

                if user.role == 'admin':
                    return redirect('admin_dashboard')
                elif user.role == 'doctor':
                    return redirect('doctor_dashboard')
                elif user.role == 'patient':
                    return redirect('patient_dashboard')
                else:
                    messages.error(request, 'Your account has an undefined role. Please contact support.')
                    logout(request)
                    return redirect('login')
            else:
                messages.error(request, "Invalid username or password.")
        else:
            messages.error(request, "Please enter valid credentials.")
    else: # GET request
        form = AuthenticationForm()

    return render(request, 'index.html', {'form': form})


def user_logout(request):
    """
    Handles user logout.
    """
    auth_logout(request)
    messages.info(request, "You have been logged out successfully.")
    return redirect('login') # Redirect to login page after logout

def forget_password(request):
    """
    Handles sending password reset emails.
    """
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = CustomUser.objects.get(email=email)

            current_site = get_current_site(request)
            subject = 'Password Reset Request for MediDash'
            # Ensure 'registration/' is correct path to your email template
            message = render_to_string('registration/password_reset_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
                'protocol': 'https' if request.is_secure() else 'http',
            })
            send_mail(subject, message, settings.EMAIL_HOST_USER, [email])
            messages.success(request, "If an account with that email exists, a password reset link has been sent to your email.")
            # Ensure 'registration/password_reset_done.html' is correct path
            return render(request, 'registration/password_reset_done.html')
        except CustomUser.DoesNotExist:
            messages.error(request, "No user found with that email address.")
            return render(request, 'forget_password.html') # Render the form again with error
        except Exception as e:
            messages.error(request, f"An error occurred: {e}")
            return render(request, 'forget_password.html') # Render the form again with error
    return render(request, 'forget_password.html')

def password_reset_done(request):
    # Ensure 'registration/password_reset_done.html' is correct path
    return render(request, 'registration/password_reset_done.html')

def password_reset_confirm(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = CustomUser.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')

            if new_password and new_password == confirm_password:
                user.set_password(new_password)
                user.save()
                messages.success(request, "Your password has been reset successfully. You can now log in with your new password.")
                # Ensure 'password_reset_complete' URL is defined and points to a template
                return redirect('password_reset_complete')
            else:
                messages.error(request, "Passwords do not match or are empty.")
        # Ensure 'registration/password_reset_confirm.html' is correct path
        return render(request, 'registration/password_reset_confirm.html', {'uidb64': uidb64, 'token': token})
    else:
        messages.error(request, "The password reset link is invalid or has expired.")
        # Ensure 'registration/password_reset_invalid.html' is correct path
        return render(request, 'registration/password_reset_invalid.html')

def password_reset_complete(request):
    # Ensure 'registration/password_reset_complete.html' is correct path
    return render(request, 'registration/password_reset_complete.html')


# --- Admin Views ---

@login_required(login_url='login')
@user_passes_test(is_admin, login_url='access_denied')
def admin_dashboard(request):
    """Admin panel home page."""
    doctors_count = DoctorProfile.objects.count()
    patients_count = PatientProfile.objects.count()
    devices_count = Device.objects.count()
    pending_alerts_count = Alert.objects.filter(status='pending').count()
    
    recent_registrations = SystemNotification.objects.filter(
        notification_type__in=['user_registration', 'doctor_registration', 'patient_registration']
    ).order_by('-timestamp')[:5]
    recent_device_updates = SystemNotification.objects.filter(
        notification_type__in=['device_registered', 'device_offline', 'device_data_sync']
    ).order_by('-timestamp')[:5]

    current_hour = timezone.now().hour
    if current_hour >= 5 and current_hour < 12:
        greeting_text = "Good Morning"
    elif current_hour >= 12 and current_hour < 17:
        greeting_text = "Good Afternoon"
    elif current_hour >= 17 and current_hour < 20:
        greeting_text = "Good Evening"
    else:
        greeting_text = "Hello"

    unread_notifications_count = SystemNotification.objects.filter(
        recipient=request.user,
        is_read=False
    ).count() if request.user.is_authenticated else 0

    context = {
        'greeting_text': f"{greeting_text}, Admin!",
        'total_doctors': doctors_count,
        'total_patients': patients_count,
        'total_devices': devices_count,
        'active_alerts_count': pending_alerts_count,
        'offline_devices_count': Device.objects.filter(is_active=False).count(),
        'online_devices_count': Device.objects.filter(is_active=True).count(),

        'username': request.user.username,
        'profile_pic_url': 'https://placehold.co/40x40/f0f4f7/556080?text=AD',
        'unread_notifications_count': unread_notifications_count,
        'recent_activities': recent_registrations, 
    }
    return render(request, 'admin/admin-panel.html', context) # Adjusted path

@login_required(login_url='login')
@user_passes_test(is_admin, login_url='access_denied')
def admin_register_user(request):
    """
    Handles registration of new doctors and patients by admin.
    """
    doctor_form = DoctorRegistrationForm()
    patient_form = PatientRegistrationForm()
    
    # REMOVE these lines as passwords are now entered via the form
    # temp_password_doctor = None
    # temp_password_patient = None

    if request.method == 'POST':
        if 'register_doctor' in request.POST:
            doctor_form = DoctorRegistrationForm(request.POST, request.FILES)
            if doctor_form.is_valid():
                with transaction.atomic():
                    # Get password from cleaned data provided by the form
                    password = doctor_form.cleaned_data['password']
                    
                    doctor_user = CustomUser.objects.create_user(
                        username=doctor_form.cleaned_data['email'],
                        email=doctor_form.cleaned_data['email'],
                        first_name=doctor_form.cleaned_data['full_name'].split(' ')[0] if ' ' in doctor_form.cleaned_data['full_name'] else doctor_form.cleaned_data['full_name'],
                        last_name=doctor_form.cleaned_data['full_name'].split(' ')[-1] if ' ' in doctor_form.cleaned_data['full_name'] else '',
                        role='doctor',
                        password=password # Use the password from the form
                    )
                    doctor_user.save()

                    DoctorProfile.objects.create(
                        user=doctor_user,
                        specialty=doctor_form.cleaned_data['specialty'],
                        contact_number=doctor_form.cleaned_data['phone'],
                        bio=doctor_form.cleaned_data['bio'],
                        profile_picture=doctor_form.cleaned_data['profile_pic'] if doctor_form.cleaned_data['profile_pic'] else None
                    )
                    SystemNotification.objects.create(
                        recipient=request.user,
                        message=f"New Doctor {doctor_user.username} registered by Admin.",
                        notification_type='doctor_registration'
                    )
                # Modify success message as password is now user-provided, not randomly generated
                messages.success(request, f"Doctor {doctor_form.cleaned_data['full_name']} registered successfully!")
                # Removed redirect here to allow page to re-render (e.g., show empty form)
            else:
                messages.error(request, f"Error registering doctor: {doctor_form.errors.as_text()}")

        elif 'register_patient' in request.POST:
            patient_form = PatientRegistrationForm(request.POST, request.FILES)
            if patient_form.is_valid():
                with transaction.atomic():
                    # Get password from cleaned data provided by the form
                    password = patient_form.cleaned_data['password']

                    patient_user = CustomUser.objects.create_user(
                        username=patient_form.cleaned_data['email'],
                        email=patient_form.cleaned_data['email'],
                        first_name=patient_form.cleaned_data['full_name'].split(' ')[0] if ' ' in patient_form.cleaned_data['full_name'] else patient_form.cleaned_data['full_name'],
                        last_name=patient_form.cleaned_data['full_name'].split(' ')[-1] if ' ' in patient_form.cleaned_data['full_name'] else '',
                        role='patient',
                        password=password # Use the password from the form
                    )
                    patient_user.save()

                    # Save selected doctor (add doctor field to PatientProfile if not present)
                    PatientProfile.objects.create(
                        user=patient_user,
                        date_of_birth=patient_form.cleaned_data['dob'],
                        gender=patient_form.cleaned_data['gender'],
                        blood_group=patient_form.cleaned_data['blood_group'],
                        contact_number=patient_form.cleaned_data['phone'],
                        medical_history=patient_form.cleaned_data['medical_conditions'],
                        emergency_contact_name=patient_form.cleaned_data['emergency_name'],
                        emergency_contact_relationship=patient_form.cleaned_data['relationship'],
                        emergency_contact_phone=patient_form.cleaned_data['emergency_phone'],
                        profile_picture=patient_form.cleaned_data['profile_pic'] if patient_form.cleaned_data['profile_pic'] else None,
                        doctor=patient_form.cleaned_data['doctor']
                    )
                    SystemNotification.objects.create(
                        recipient=request.user,
                        message=f"New Patient {patient_user.username} registered by Admin.",
                        notification_type='patient_registration'
                    )
                # Modify success message as password is now user-provided, not randomly generated
                messages.success(request, f"Patient {patient_form.cleaned_data['full_name']} registered successfully!")
                # Removed redirect here to allow page to re-render
            else:
                messages.error(request, f"Error registering patient: {patient_form.errors.as_text()}")
        else:
            messages.error(request, "Invalid form submission. Please try again.")

    context = {
        'doctor_form': doctor_form,
        'patient_form': patient_form,
        'username': request.user.username,
        'profile_pic_url': 'https://placehold.co/40x40/f0f4f7/556080?text=AD',
        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
        # REMOVE these context variables as the password is no longer randomly generated
        # and displayed this way
        # 'temp_password_doctor': temp_password_doctor,
        # 'temp_password_patient': temp_password_patient,
    }
    return render(request, 'admin/register-user.html', context)

@login_required(login_url='login')
@user_passes_test(is_admin, login_url='access_denied')
def admin_register_device(request):
    """Handles registration of new devices."""
    form = DeviceRegistrationForm()

    if request.method == 'POST':
        form = DeviceRegistrationForm(request.POST)
        if form.is_valid():
            assigned_patient = None
            if form.cleaned_data['assigned_patient_id']:
                try:
                    patient_user = CustomUser.objects.get(pk=form.cleaned_data['assigned_patient_id'], role='patient')
                    assigned_patient = PatientProfile.objects.get(user=patient_user)
                except (CustomUser.DoesNotExist, PatientProfile.DoesNotExist):
                    messages.error(request, "Assigned Patient ID not found or is not a patient.")
                    context = {
                        'form': form,
                        'username': request.user.username,
                        'profile_pic_url': 'https://placehold.co/40x40/f0f4f7/556080?text=AD',
                        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
                    }
                    return render(request, 'admin/register-device.html', context) # Adjusted path
            
            Device.objects.create(
                patient=assigned_patient,
                device_name=form.cleaned_data['device_name'],
                mac_address=form.cleaned_data['mac_address'],
                device_location=form.cleaned_data['device_location'],
                device_description=form.cleaned_data['device_description'],
                device_type='Generic',
                is_active=True,
            )
            SystemNotification.objects.create(
                recipient=request.user,
                message=f"New device {form.cleaned_data['device_name']} registered by Admin.",
                notification_type='device_registered'
            )
            messages.success(request, f"Device {form.cleaned_data['device_name']} registered successfully!")
            return redirect('admin_register_device')
        else:
            messages.error(request, f"Error registering device: {form.errors.as_text()}")
    
    context = {
        'form': form,
        'username': request.user.username,
        'profile_pic_url': 'https://placehold.co/40x40/f0f4f7/556080?text=AD',
        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
    }
    return render(request, 'admin/register-device.html', context) # Adjusted path

@login_required(login_url='login')
@user_passes_test(is_admin, login_url='access_denied')
def admin_view_records(request):
    """View to display patient and doctor records for admin."""
    doctors = []
    patients = []

    for doc_profile in DoctorProfile.objects.all().order_by('user__first_name'):
        doctors.append({
            'id': doc_profile.user.id,
            'full_name': doc_profile.user.get_full_name(),
            'specialty': doc_profile.specialty,
            'email': doc_profile.user.email,
            'status': doc_profile.status,
            'profile_picture': doc_profile.profile_picture.url if doc_profile.profile_picture else ''
        })

    for pat_profile in PatientProfile.objects.all().order_by('user__first_name'):
        age = (timezone.now().year - pat_profile.date_of_birth.year) if pat_profile.date_of_birth else 'N/A'
        last_visit_obj = MedicalRecord.objects.filter(patient=pat_profile).order_by('-record_date').first()
        last_visit = last_visit_obj.record_date.strftime("%Y-%m-%d") if last_visit_obj else 'N/A'
        # Get assigned devices
        devices = pat_profile.devices.all()
        device_names = ', '.join([device.device_name for device in devices]) if devices else 'None'
        patients.append({
            'id': pat_profile.user.id,
            'full_name': pat_profile.user.get_full_name(),
            'age': age,
            'gender': pat_profile.gender,
            'condition': pat_profile.medical_history,
            'last_visit': last_visit,
            'status': pat_profile.status,
            'profile_picture': pat_profile.profile_picture.url if pat_profile.profile_picture else '',
            'devices': device_names,
        })

    context = {
        'doctors': json.dumps(doctors),
        'patients': json.dumps(patients),
        'username': request.user.username,
        'profile_pic_url': 'https://placehold.co/40x40/f0f4f7/556080?text=AD',
        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
    }
    return render(request, 'admin/records.html', context) # Adjusted path

@login_required(login_url='login')
@user_passes_test(is_admin, login_url='access_denied')
def admin_notifications(request):
    """View for admin notifications."""
    if request.method == 'POST':
        if 'remove_all' in request.POST:
            SystemNotification.objects.filter(recipient=request.user).delete()
            return redirect('admin_notifications')
        notification_id = request.POST.get('notification_id')
        if notification_id:
            try:
                notification = SystemNotification.objects.get(id=notification_id, recipient=request.user)
                if 'mark_read' in request.POST:
                    notification.is_read = True
                    notification.save()
                elif 'dismiss' in request.POST:
                    notification.delete()
            except SystemNotification.DoesNotExist:
                pass
        return redirect('admin_notifications')
    notifications = SystemNotification.objects.filter(recipient=request.user).order_by('-timestamp')
    context = {
        'notifications': notifications,
        'username': request.user.username,
        'profile_pic_url': 'https://placehold.co/40x40/f0f4f7/556080?text=AD',
        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
    }
    return render(request, 'admin/notfications.html', context) # Adjusted path

@login_required(login_url='login')
@user_passes_test(is_admin, login_url='access_denied')
def admin_settings(request):
    """View for admin settings."""
    user = request.user
    user_profile_form = UserProfileForm()
    security_form = SecurityForm()
    notification_settings_form = AdminNotificationSettingsForm(instance=user)
    site_settings, _ = SiteSettings.objects.get_or_create(pk=1)
    site_settings_form = SiteSettingsForm(instance=site_settings)

    if request.method == 'POST':
        if 'update_profile' in request.POST:
            user_profile_form = UserProfileForm(request.POST, request.FILES)
            if user_profile_form.is_valid():
                user.first_name = user_profile_form.cleaned_data['full_name'].split(' ')[0]
                user.middle_name = user_profile_form.cleaned_data.get('middle_name', '')
                user.last_name = user_profile_form.cleaned_data['full_name'].split(' ')[-1] if ' ' in user_profile_form.cleaned_data['full_name'] else ''
                user.email = user_profile_form.cleaned_data['email']
                user.save()
                messages.success(request, 'Admin profile updated successfully!')
                return redirect('admin_settings')
            else:
                messages.error(request, f"Error updating admin profile: {user_profile_form.errors.as_text()}")

        elif 'update_security' in request.POST:
            security_form = SecurityForm(request.POST)
            if security_form.is_valid():
                current_password = security_form.cleaned_data['current_password']
                new_password = security_form.cleaned_data['new_password']
                if request.user.check_password(current_password):
                    user.set_password(new_password)
                    user.save()
                    messages.success(request, 'Admin password updated successfully!')
                    return redirect('admin_settings')
                else:
                    messages.error(request, "Current password incorrect.")
            else:
                messages.error(request, f"Error updating admin security: {security_form.errors.as_text()}")

        elif 'update_notifications' in request.POST:
            notification_settings_form = AdminNotificationSettingsForm(request.POST, instance=user)
            if notification_settings_form.is_valid():
                notification_settings_form.save()
                messages.success(request, 'Admin notification settings updated!')
                return redirect('admin_settings')
            else:
                messages.error(request, f"Error updating admin notifications: {notification_settings_form.errors.as_text()}")

        elif 'update_site_settings' in request.POST:
            site_settings_form = SiteSettingsForm(request.POST, instance=site_settings)
            if site_settings_form.is_valid():
                site_settings_form.save()
                messages.success(request, 'General site settings updated!')
                return redirect('admin_settings')
            else:
                messages.error(request, f"Error updating site settings: {site_settings_form.errors.as_text()}")

        elif 'delete_account' in request.POST:
            user.delete()
            messages.success(request, 'Admin account deleted.')
            return redirect('login')

    context = {
        'user_profile_form': user_profile_form,
        'security_form': security_form,
        'notification_settings_form': notification_settings_form,
        'site_settings_form': site_settings_form,
        'username': request.user.username,
        'profile_pic_url': 'https://placehold.co/40x40/f0f4f7/556080?text=AD',
        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
        'synced_devices': Device.objects.all(),
    }
    return render(request, 'admin/settings.html', context)

@login_required(login_url='login')
@user_passes_test(is_admin, login_url='access_denied')
def admin_doctor_details(request, doctor_id):
    """Admin view for detailed doctor info."""
    doctor_profile = get_object_or_404(DoctorProfile, user__id=doctor_id)
    context = {
        'doctor': doctor_profile,
        'username': request.user.username,
        'profile_pic_url': 'https://placehold.co/40x40/f0f4f7/556080?text=AD',
        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
    }
    return render(request, 'admin/doctor_details.html', context)

@login_required(login_url='login')
@user_passes_test(is_admin, login_url='access_denied')
def admin_patient_details(request, patient_id):
    """Admin view for detailed patient info."""
    patient_profile = get_object_or_404(PatientProfile, user__id=patient_id)
    devices = patient_profile.devices.all()
    context = {
        'patient': patient_profile,
        'devices': devices,
        'username': request.user.username,
        'profile_pic_url': 'https://placehold.co/40x40/f0f4f7/556080?text=AD',
        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
    }
    return render(request, 'admin/patient_details.html', context)

@login_required(login_url='login')
@user_passes_test(is_admin, login_url='access_denied')
def admin_edit_doctor(request, doctor_id):
    doctor_profile = get_object_or_404(DoctorProfile, user__id=doctor_id)
    if request.method == 'POST':
        form = DoctorUpdateForm(request.POST, request.FILES, instance=doctor_profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'Doctor profile updated successfully!')
            return redirect('admin_view_records')
    else:
        form = DoctorUpdateForm(instance=doctor_profile)
    context = {
        'form': form,
        'doctor': doctor_profile,
        'username': request.user.username,
        'profile_pic_url': 'https://placehold.co/40x40/f0f4f7/556080?text=AD',
        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
    }
    return render(request, 'admin/edit_doctor.html', context)

@login_required(login_url='login')
@user_passes_test(is_admin, login_url='access_denied')
def admin_edit_patient(request, patient_id):
    patient_profile = get_object_or_404(PatientProfile, user__id=patient_id)
    if request.method == 'POST':
        form = PatientUpdateForm(request.POST, request.FILES, instance=patient_profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'Patient profile updated successfully!')
            return redirect('admin_view_records')
    else:
        form = PatientUpdateForm(instance=patient_profile)
    # Get all devices assigned to this patient
    devices = patient_profile.devices.all()
    context = {
        'form': form,
        'patient': patient_profile,
        'devices': devices,
        'username': request.user.username,
        'profile_pic_url': 'https://placehold.co/40x40/f0f4f7/556080?text=AD',
        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
    }
    return render(request, 'admin/edit_patient.html', context)

@login_required(login_url='login')
@user_passes_test(is_admin, login_url='access_denied')
@require_POST
def admin_delete_device(request, device_id):
    device = get_object_or_404(Device, id=device_id)
    patient_id = device.patient.user.id if device.patient else None
    device.delete()
    messages.success(request, "Device deleted successfully.")
    if patient_id:
        return redirect(reverse('admin_edit_patient', args=[patient_id]))
    return redirect('admin_view_records')

@login_required(login_url='login')
@user_passes_test(is_admin, login_url='access_denied')
@require_POST
def admin_delete_patient(request, patient_id):
    patient = get_object_or_404(PatientProfile, user__id=patient_id)
    # Delete all devices assigned to this patient
    patient.devices.all().delete()
    patient.user.delete()  # This will also delete the PatientProfile
    messages.success(request, "Patient and their devices deleted successfully.")
    return redirect('admin_view_records')

@login_required(login_url='login')
@user_passes_test(is_admin, login_url='access_denied')
@require_POST
def admin_delete_doctor(request, doctor_id):
    doctor_profile = get_object_or_404(DoctorProfile, user__id=doctor_id)
    doctor_profile.user.delete()  # This will also delete the DoctorProfile
    messages.success(request, "Doctor deleted successfully.")
    return redirect('admin_view_records')


# --- Doctor Views ---
@login_required(login_url='login')
@user_passes_test(is_doctor, login_url='access_denied')
def doctor_dashboard(request):
    doctor_profile = get_object_or_404(DoctorProfile, user=request.user)
    total_patients = PatientProfile.objects.count()
    pending_alerts = Alert.objects.filter(status='pending').count()
    recent_alerts = Alert.objects.filter(status='pending').order_by('-timestamp')[:5]
    current_hour = timezone.now().hour
    if current_hour >= 5 and current_hour < 12:
        greeting_text = "Good Morning"
    elif current_hour >= 12 and current_hour < 17:
        greeting_text = "Good Afternoon"
    elif current_hour >= 17 and current_hour < 20:
        greeting_text = "Good Evening"
    else:
        greeting_text = "Hello"
    unread_notifications_count = SystemNotification.objects.filter(recipient=request.user, is_read=False).count()

    # Unassigned patients
    unassigned_patients = PatientProfile.objects.filter(doctor__isnull=True)
    if request.method == 'POST' and 'assign_patient_id' in request.POST:
        patient_id = request.POST.get('assign_patient_id')
        try:
            patient = PatientProfile.objects.get(pk=patient_id)
            patient.doctor = doctor_profile
            patient.save()
            messages.success(request, f"You have been assigned to patient {patient.user.get_full_name()}.")
            return redirect('doctor_dashboard')
        except PatientProfile.DoesNotExist:
            messages.error(request, "Patient not found.")

    context = {
        'greeting_text': f"{greeting_text}, Dr. {request.user.last_name or request.user.username}!",
        'total_patients': total_patients,
        'pending_alerts': pending_alerts,
        'recent_alerts': recent_alerts,
        'username': request.user.username,
        'profile_pic_url': doctor_profile.profile_picture.url if doctor_profile.profile_picture else 'https://placehold.co/40x40/f0f4f7/556080?text=DR',
        'unread_notifications_count': unread_notifications_count,
        'unassigned_patients': unassigned_patients,
    }
    return render(request, 'doctor/doctor.html', context)

@login_required(login_url='login')
@user_passes_test(is_doctor, login_url='access_denied')
def doctor_patients_list(request):
    """Lists all patients for a doctor."""
    patients = PatientProfile.objects.all().order_by('user__first_name')
    doctor_profile = get_object_or_404(DoctorProfile, user=request.user)
    context = {
        'patients': patients,
        'username': request.user.username,
        'profile_pic_url': doctor_profile.profile_picture.url if doctor_profile.profile_picture else 'https://placehold.co/40x40/f0f4f7/556080?text=DR',
        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
    }
    return render(request, 'doctor/patients.html', context) # Adjusted template name

@login_required(login_url='login')
@user_passes_test(is_doctor, login_url='access_denied')
def doctor_patient_detail(request, patient_id):
    """Displays detailed information about a single patient for a doctor."""
    patient = get_object_or_404(PatientProfile, user__id=patient_id)
    vitals = VitalSign.objects.filter(patient=patient).order_by('-timestamp')
    medical_records = MedicalRecord.objects.filter(patient=patient).order_by('-record_date')
    alerts = Alert.objects.filter(patient=patient).order_by('-timestamp')
    reports = Report.objects.filter(patient=patient).order_by('-report_date')
    doctor_profile = get_object_or_404(DoctorProfile, user=request.user)

    context = {
        'patient': patient,
        'vitals': vitals,
        'medical_records': medical_records,
        'alerts': alerts,
        'reports': reports,
        'username': request.user.username,
        'profile_pic_url': doctor_profile.profile_picture.url if doctor_profile.profile_picture else 'https://placehold.co/40x40/f0f4f7/556080?text=DR',
        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
    }
    return render(request, 'doctor/patient_doctor.html', context) # Adjusted template name

@login_required(login_url='login')
@user_passes_test(is_doctor, login_url='access_denied')
def doctor_alerts(request):
    """Lists alerts for the doctor and handles alert actions."""
    alerts = Alert.objects.filter(Q(status='pending') | Q(assigned_to=request.user)).order_by('-timestamp')
    high_severity_alerts = alerts.filter(severity__in=['high', 'critical'])
    context = {
        'alerts': alerts,
        'high_severity_alerts_count': high_severity_alerts.count(),
    }
    return render(request, 'doctor/alerts.html', context) # Adjusted template name

@login_required(login_url='login')
@user_passes_test(is_doctor, login_url='access_denied')
def doctor_reports(request):
    """Handles viewing and generating reports by doctors."""
    patients = PatientProfile.objects.all().order_by('user__first_name')
    reports = Report.objects.filter(doctor__user=request.user).order_by('-report_date')
    doctor_profile = get_object_or_404(DoctorProfile, user=request.user)

    today_date = timezone.now().date()

    if request.method == 'POST':
        patient_id = request.POST.get('patient_id')
        title = request.POST.get('title')
        chief_complaint = request.POST.get('chiefComplaint')
        diagnosis = request.POST.get('diagnosis')
        treatment_plan = request.POST.get('treatmentPlan')
        notes = request.POST.get('notes')
        
        try:
            patient = PatientProfile.objects.get(user__id=patient_id)
            Report.objects.create(
                patient=patient,
                doctor=doctor_profile,
                title=title,
                chief_complaint=chief_complaint,
                diagnosis=diagnosis,
                treatment_plan=treatment_plan,
                notes=notes,
                report_date=today_date
            )
            messages.success(request, "Report generated successfully!")
            return redirect('doctor_reports')
        except PatientProfile.DoesNotExist:
            messages.error(request, "Selected patient does not exist.")
        except Exception as e:
            messages.error(request, f"Error generating report: {e}")
    
    context = {
        'patients': patients,
        'reports': reports,
        'username': request.user.username,
        'profile_pic_url': doctor_profile.profile_picture.url if doctor_profile.profile_picture else 'https://placehold.co/40x40/f0f4f7/556080?text=DR',
        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
        'today_date': today_date,
    }
    return render(request, 'doctor/reports.html', context) # Adjusted template name

@login_required(login_url='login')
@user_passes_test(is_doctor, login_url='access_denied')
def doctor_notifications(request):
    """View for doctor notifications with mark all as read and filter toggle."""
    filter_state = request.GET.get('filter', 'unread')  # 'unread' or 'read'
    if request.method == 'POST' and request.POST.get('action') == 'mark_all_read':
        SystemNotification.objects.filter(recipient=request.user, is_read=False).update(is_read=True)
    if filter_state == 'read':
        notifications = SystemNotification.objects.filter(recipient=request.user, is_read=True).order_by('-timestamp')
    else:
        notifications = SystemNotification.objects.filter(recipient=request.user, is_read=False).order_by('-timestamp')
    doctor_profile = get_object_or_404(DoctorProfile, user=request.user)
    context = {
        'notifications': notifications,
        'username': request.user.username,
        'profile_pic_url': doctor_profile.profile_picture.url if doctor_profile.profile_picture else 'https://placehold.co/40x40/f0f4f7/556080?text=DR',
        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
        'filter_state': filter_state,
    }
    return render(request, 'doctor/notfications_doctor.html', context)

@login_required(login_url='login')
@user_passes_test(is_doctor, login_url='access_denied')
def doctor_settings(request):
    """View for doctor settings."""
    doctor_profile = get_object_or_404(DoctorProfile, user=request.user)
    user = request.user

    # Use DoctorUpdateForm for profile editing
    if request.method == 'POST' and 'update_profile' in request.POST:
        doctor_update_form = DoctorUpdateForm(request.POST, request.FILES, instance=doctor_profile)
        if doctor_update_form.is_valid():
            doctor_update_form.save()
            messages.success(request, "Profile settings updated successfully!")
            return redirect('doctor_settings')
        else:
            messages.error(request, f"Error updating profile: {doctor_update_form.errors.as_text()}")
    else:
        doctor_update_form = DoctorUpdateForm(instance=doctor_profile)

    # Keep the other forms as before
    notification_initial_data = {
        'email_notifications': doctor_profile.email_notifications_enabled,
        'sms_alerts': doctor_profile.sms_notifications_enabled,
        'push_notifications': doctor_profile.push_notifications_enabled,
    }
    security_initial_data = {
        'two_factor_authentication': doctor_profile.two_factor_authentication_enabled
    }
    security_form = SecurityForm(initial=security_initial_data)
    notification_settings_form = NotificationSettingsForm(initial=notification_initial_data)

    synced_devices = Device.objects.filter(patient__user__isnull=False)

    context = {
        'doctor_update_form': doctor_update_form,
        'security_form': security_form,
        'notification_settings_form': notification_settings_form,
        'doctor_profile': doctor_profile,
        'username': request.user.username,
        'profile_pic_url': doctor_profile.profile_picture.url if doctor_profile.profile_picture else 'https://placehold.co/40x40/f0f4f7/556080?text=DR',
        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
        'synced_devices': synced_devices,
    }
    return render(request, 'doctor/settings_doctor.html', context) # Adjusted template name

@login_required(login_url='login')
@user_passes_test(is_doctor, login_url='access_denied')
def doctor_patient_message(request, patient_id):
    patient = get_object_or_404(CustomUser, id=patient_id)
    doctor = request.user
    # Fetch all messages between doctor and patient
    messages = Message.objects.filter(
        (Q(sender=doctor) & Q(recipient=patient)) |
        (Q(sender=patient) & Q(recipient=doctor))
    ).order_by('timestamp')

    if request.method == 'POST':
        text = request.POST.get('message')
        if text:
            Message.objects.create(sender=doctor, recipient=patient, text=text, timestamp=timezone.now())
            return redirect('doctor_patient_message', patient_id=patient.id)

    return render(request, 'doctor/messages.html', {
        'patient': patient,
        'messages': messages,
    })

@login_required(login_url='login')
@user_passes_test(is_doctor, login_url='access_denied')
def edit_emergency_info(request, patient_id):
    patient = get_object_or_404(PatientProfile, user_id=patient_id)
    if request.method == 'POST':
        patient.emergency_contact_name = request.POST.get('emergency_contact_name')
        patient.emergency_contact_relationship = request.POST.get('emergency_contact_relationship')
        patient.emergency_contact_phone = request.POST.get('emergency_contact_phone')
        patient.medical_history = request.POST.get('medical_history')
        patient.save()
        return redirect('doctor_patient_detail', patient_id=patient_id)
    return render(request, 'doctor/edit_emergency_info.html', {'patient': patient})

@login_required(login_url='login')
@user_passes_test(is_doctor, login_url='access_denied')
def add_medical_record(request, patient_id):
    patient = get_object_or_404(PatientProfile, user_id=patient_id)
    doctor = get_object_or_404(DoctorProfile, user=request.user)
    if request.method == 'POST':
        record_type = request.POST.get('record_type')
        record_date = request.POST.get('record_date') or timezone.now().date()
        title = request.POST.get('title')
        description = request.POST.get('description')
        MedicalRecord.objects.create(
            patient=patient,
            doctor=doctor,
            record_type=record_type,
            record_date=record_date,
            title=title,
            description=description
        )
        return redirect('doctor_patient_detail', patient_id=patient_id)
    return render(request, 'doctor/add_medical_record.html', {'patient': patient})

@login_required(login_url='login')
@user_passes_test(is_doctor, login_url='access_denied')
def doctor_change_password(request):
    return render(request, 'doctor/change_password.html')

@login_required(login_url='login')
@user_passes_test(is_doctor, login_url='access_denied')
def doctor_enable_2fa(request):
    return render(request, 'doctor/enable_2fa.html')

@login_required(login_url='login')
@user_passes_test(is_doctor, login_url='access_denied')
def doctor_delete_account(request):
    return render(request, 'doctor/delete_account.html')


# --- Patient Views ---
@login_required(login_url='login')
@user_passes_test(is_patient, login_url='access_denied')
def patient_dashboard(request):
    """Patient's dashboard."""
    patient_profile = get_object_or_404(PatientProfile, user=request.user)
    recent_vitals = VitalSign.objects.filter(patient=patient_profile).order_by('-timestamp')[:5]
    latest_vital = recent_vitals.first()
    recent_alerts = Alert.objects.filter(patient=patient_profile, status='pending').order_by('-timestamp')[:3]
    unread_messages_count = Message.objects.filter(recipient=request.user, is_read=False).count()
    
    current_hour = timezone.now().hour
    if current_hour >= 5 and current_hour < 12:
        greeting_text = "Good Morning"
    elif current_hour >= 12 and current_hour < 17:
        greeting_text = "Good Afternoon"
    elif current_hour >= 17 and current_hour < 20:
        greeting_text = "Good Evening"
    else:
        greeting_text = "Hello"

    unread_notifications_count = SystemNotification.objects.filter(recipient=request.user, is_read=False).count()

    context = {
        'greeting_text': f"{greeting_text}, {request.user.first_name or request.user.username}!",
        'patient_profile': patient_profile,
        'recent_vitals': recent_vitals,
        'latest_vital': latest_vital,
        'recent_alerts': recent_alerts,
        'unread_messages_count': unread_messages_count,
        'username': request.user.username,
        'profile_pic_url': patient_profile.profile_picture.url if patient_profile.profile_picture else 'https://placehold.co/40x40/f0f4f7/556080?text=PT',
        'unread_notifications_count': unread_notifications_count,
    }
    return render(request, 'patient/patient_dashboard.html', context) # Adjusted template name

@login_required(login_url='login')
@user_passes_test(is_patient, login_url='access_denied')
def patient_vitals_history(request):
    """Displays patient's vital signs history."""
    patient_profile = get_object_or_404(PatientProfile, user=request.user)
    vitals = VitalSign.objects.filter(patient=patient_profile).order_by('-timestamp')

    # Advanced grouping: latest 10 per type
    N = 10
    vitals_by_type = defaultdict(list)
    for vital in vitals:
        if len(vitals_by_type[vital.vital_type]) < N:
            vitals_by_type[vital.vital_type].append(vital)
        # Stop if all types have N
        if len(vitals_by_type) >= 3 and all(len(v) >= N for v in vitals_by_type.values()):
            break

    # Flatten and sort by timestamp (oldest first)
    chart_vitals = []
    for vitals_list in vitals_by_type.values():
        chart_vitals.extend(vitals_list)
    chart_vitals = sorted(chart_vitals, key=lambda v: v.timestamp)

    latest_vitals = vitals[:3]  # Only the latest 3 vitals for the table
    context = {
        'vitals': vitals,
        'latest_vitals': latest_vitals,
        'chart_vitals': chart_vitals,
        'username': request.user.username,
        'profile_pic_url': patient_profile.profile_picture.url if patient_profile.profile_picture else 'https://placehold.co/40x40/f0f4f7/556080?text=PT',
        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
    }
    return render(request, 'patient/vitals-history.html', context)

@login_required(login_url='login')
@user_passes_test(is_patient, login_url='access_denied')
def patient_health_records(request):
    """Displays patient's medical records."""
    patient_profile = get_object_or_404(PatientProfile, user=request.user)
    medical_records = MedicalRecord.objects.filter(patient=patient_profile).order_by('-record_date')
    context = {
        'medical_records': medical_records,
        'username': request.user.username,
        'profile_pic_url': patient_profile.profile_picture.url if patient_profile.profile_picture else 'https://placehold.co/40x40/f0f4f7/556080?text=PT',
        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
    }
    return render(request, 'patient/health-records.html', context) # Adjusted template name

@login_required(login_url='login')
@user_passes_test(is_patient, login_url='access_denied')
def patient_messages(request):
    """Handles patient's messages (inbox and compose)."""
    # from django.contrib import messages
    # messages.success(request, "This is a test message!")
    received_messages = Message.objects.filter(recipient=request.user).order_by('-timestamp')
    sent_messages = Message.objects.filter(sender=request.user).order_by('-timestamp')
    
    if request.method == 'GET' and 'message_id' in request.GET:
        message_id = request.GET.get('message_id')
        try:
            message_to_mark_read = Message.objects.get(id=message_id, recipient=request.user)
            if not message_to_mark_read.is_read:
                message_to_mark_read.is_read = True
                message_to_mark_read.save()
                messages.success(request, "Message marked as read.")
        except Message.DoesNotExist:
            messages.error(request, "Message not found or you don't have permission to view it.")
        return redirect('patient_messages') 

    if request.method == 'POST':
        subject = request.POST.get('subject')
        body = request.POST.get('body')
        recipient_username = request.POST.get('recipient')
        
        if not subject or not body or not recipient_username:
            messages.error(request, "Please fill in all fields (Recipient, Subject, and Message Body).")
        else:
            try:
                recipient_user = CustomUser.objects.get(username=recipient_username)
                if recipient_user == request.user:
                    messages.error(request, "You cannot send a message to yourself.")
                else:
                    Message.objects.create(sender=request.user, recipient=recipient_user, subject=subject, body=body)
                    messages.success(request, "Message sent successfully!")
            except CustomUser.DoesNotExist:
                messages.error(request, "Recipient user not found.")
            except Exception as e:
                messages.error(request, f"Error sending message: {e}")
        return redirect('patient_messages') 
    
    context = {
        'received_messages': received_messages,
        'sent_messages': sent_messages,
        'username': request.user.username,
        'profile_pic_url': request.user.patientprofile.profile_picture.url if hasattr(request.user, 'patientprofile') and request.user.patientprofile.profile_picture else 'https://placehold.co/40x40/f0f4f7/556080?text=PT',
        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
    }
    return render(request, 'patient/messages.html', context) # Adjusted template name

@login_required(login_url='login')
@user_passes_test(is_patient, login_url='access_denied')
def patient_notifications(request):
    """View for patient notifications."""
    notifications = SystemNotification.objects.filter(recipient=request.user).order_by('-timestamp')
    patient_profile = get_object_or_404(PatientProfile, user=request.user)
    context = {
        'notifications': notifications,
        'username': request.user.username,
        'profile_pic_url': patient_profile.profile_picture.url if patient_profile.profile_picture else 'https://placehold.co/40x40/f0f4f7/556080?text=PT',
        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
    }
    return render(request, 'patient/notifications_patient.html', context) # Adjusted template name


@login_required(login_url='login')
@user_passes_test(is_patient, login_url='access_denied')
def patient_profile(request):
    """Patient's profile and settings."""
    patient_profile = get_object_or_404(PatientProfile, user=request.user)
    user = request.user

    user_profile_initial_data = {
        'full_name': user.get_full_name(),
        'email': user.email,
        'profile_pic': patient_profile.profile_picture,
    }
    notification_initial_data = {
        'email_notifications': patient_profile.email_notifications_enabled,
        'sms_alerts': patient_profile.sms_notifications_enabled,
        'push_notifications': patient_profile.push_notifications_enabled,
    }
    security_initial_data = {} 

    user_profile_form = UserProfileForm(initial=user_profile_initial_data)
    security_form = SecurityForm(initial=security_initial_data)
    notification_settings_form = NotificationSettingsForm(initial=notification_initial_data)

    if request.method == 'POST':
        if 'update_profile' in request.POST:
            user_profile_form = UserProfileForm(request.POST, request.FILES, initial=user_profile_initial_data)
            if user_profile_form.is_valid():
                user.first_name = user_profile_form.cleaned_data['full_name'].split(' ')[0]
                user.last_name = user_profile_form.cleaned_data['full_name'].split(' ')[-1] if ' ' in user_profile_form.cleaned_data['full_name'] else ''
                user.email = user_profile_form.cleaned_data['email']
                user.save()

                if user_profile_form.cleaned_data['profile_pic']:
                    patient_profile.profile_picture = user_profile_form.cleaned_data['profile_pic']
                patient_profile.save()
                messages.success(request, "Profile settings updated successfully!")
                return redirect('patient_profile')
            else:
                messages.error(request, f"Error updating profile: {user_profile_form.errors.as_text()}")

        elif 'update_security' in request.POST:
            security_form = SecurityForm(request.POST, initial=security_initial_data)
            if security_form.is_valid():
                current_password = security_form.cleaned_data['current_password']
                new_password = security_form.cleaned_data['new_password']
                if user.check_password(current_password):
                    user.set_password(new_password)
                    user.save()
                    messages.success(request, "Security settings updated successfully!")
                    return redirect('patient_profile')
                else:
                    messages.error(request, "Current password incorrect.")
            else:
                messages.error(request, f"Error updating security: {security_form.errors.as_text()}")

        elif 'update_notifications' in request.POST:
            notification_settings_form = NotificationSettingsForm(request.POST, initial=notification_initial_data)
            if notification_settings_form.is_valid():
                patient_profile.email_notifications_enabled = notification_settings_form.cleaned_data['email_notifications']
                patient_profile.sms_notifications_enabled = notification_settings_form.cleaned_data['sms_alerts']
                patient_profile.push_notifications_enabled = notification_settings_form.cleaned_data['push_notifications']
                patient_profile.save()
                messages.success(request, "Notification settings updated successfully!")
                return redirect('patient_profile')
            else:
                messages.error(request, f"Error updating notification settings: {notification_settings_form.errors.as_text()}")
    
    synced_devices = Device.objects.filter(patient=patient_profile)

    context = {
        'user_profile_form': user_profile_form,
        'security_form': security_form,
        'notification_settings_form': notification_settings_form,
        'patient_profile': patient_profile,
        'username': request.user.username,
        'profile_pic_url': patient_profile.profile_picture.url if patient_profile.profile_picture else 'https://placehold.co/40x40/f0f4f7/556080?text=PT',
        'unread_notifications_count': SystemNotification.objects.filter(recipient=request.user, is_read=False).count(),
        'synced_devices': synced_devices,
    }
    return render(request, 'patient/profile.html', context) # Adjusted template name

def device_detail(request, device_id):
    device = get_object_or_404(Device, id=device_id)
    return render(request, 'doctor/device_detail.html', {'device': device})

@login_required(login_url='login')
@user_passes_test(is_patient, login_url='access_denied')
def mark_message_read(request):
    """Marks a message as read for the logged-in patient via AJAX POST."""
    if request.method == 'POST':
        message_id = request.POST.get('message_id')
        if not message_id:
            return JsonResponse({'success': False, 'error': 'No message_id provided.'})
        try:
            message = Message.objects.get(id=message_id, recipient=request.user)
            if not message.is_read:
                message.is_read = True
                message.save()
            return JsonResponse({'success': True})
        except Message.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Message not found.'})
    return JsonResponse({'success': False, 'error': 'Invalid request method.'})

@login_required(login_url='login')
@user_passes_test(is_patient, login_url='access_denied')
@require_POST
def upload_health_record(request):
    """Handles AJAX upload of a new health record document for the patient."""
    patient_profile = get_object_or_404(PatientProfile, user=request.user)
    record_type = request.POST.get('record_type')
    title = request.POST.get('title')
    description = request.POST.get('description')
    document = request.FILES.get('document')
    if not (record_type and title and document):
        return JsonResponse({'success': False, 'error': 'Missing required fields.'})
    record = MedicalRecord.objects.create(
        patient=patient_profile,
        doctor=None,  # Patient uploads are not linked to a doctor
        record_type=record_type,
        title=title,
        description=description,
        document=document
    )
    return JsonResponse({'success': True, 'record_id': record.id})

def determine_status(vital_type, value):
    try:
        value = float(value)
    except (TypeError, ValueError):
        return "Unknown"
    if vital_type == "temperature":
        if value < 36.0:
            return "Low"
        elif value > 37.5:
            return "High"
        else:
            return "Normal"
    elif vital_type in ["pulse_rate", "heart_rate"]:
        if value < 60:
            return "Low"
        elif value > 100:
            return "High"
        else:
            return "Normal"
    elif vital_type == "ecg":
        # Example: 0 = Irregular, 1 = Normal (customize as needed)
        return "Irregular" if value == 0 else "Normal"
    return "Normal"

@api_view(['POST'])
@permission_classes([AllowAny])  # You may want to restrict this in production
def esp32_vital_upload(request):
    """
    ESP32 posts: { "mac_address": "...", "vital_type": "...", "value": ..., "unit": "..." }
    """
    mac = request.data.get('mac_address')
    vital_type = request.data.get('vital_type')
    value = request.data.get('value')
    unit = request.data.get('unit')
    # Determine status based on value and type
    status_val = determine_status(vital_type, value)

    if not all([mac, vital_type, value]):
        return Response({'error': 'mac_address, vital_type, and value are required.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        device = Device.objects.get(mac_address=mac)
        patient = device.patient
        if not patient:
            return Response({'error': 'Device not assigned to any patient.'}, status=status.HTTP_400_BAD_REQUEST)
        vital = VitalSign.objects.create(
            patient=patient,
            recorded_by_device=device,
            vital_type=vital_type,
            value=value,
            unit=unit,
            status=status_val
        )
        # Send alert if status is not Normal
        if status_val.lower() != 'normal':
            message = f"Alert: {vital_type.replace('_', ' ').title()} value {value}{unit or ''} is {status_val}."
            # Notify patient
            SystemNotification.objects.create(
                recipient=patient.user,
                message=message,
                notification_type='warning'
            )
            # Notify doctor if assigned
            if patient.doctor and patient.doctor.user:
                SystemNotification.objects.create(
                    recipient=patient.doctor.user,
                    message=f"Patient {patient.user.get_full_name() or patient.user.username}: {message}",
                    notification_type='warning'
                )
            # --- EMAIL & SMS ALERTS ---
            subject = f"Health Alert: {vital_type.replace('_', ' ').title()} is {status_val}"
            email_message = (
                f"Dear {patient.user.first_name},\n"
                f"Your {vital_type.replace('_', ' ').title()} reading is {value}{unit or ''} and is marked as {status_val}.\n"
                f"Timestamp: {vital.timestamp}\n"
            )
            recipients = [patient.user.email]
            if patient.doctor and patient.doctor.user.email:
                recipients.append(patient.doctor.user.email)
            send_alert_email(subject, email_message, recipients)
            # SMS
            if patient.contact_number:
                send_alert_sms(email_message, patient.contact_number)
            if patient.doctor and patient.doctor.contact_number:
                send_alert_sms(f"Patient {patient.user.get_full_name() or patient.user.username}: {message}", patient.doctor.contact_number)
        serializer = VitalSignSerializer(vital)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    except Device.DoesNotExist:
        return Response({'error': 'Device not found.'}, status=status.HTTP_404_NOT_FOUND)

def patient_register(request):
    if request.user.is_authenticated:
        return redirect('patient_dashboard')
    form = PatientRegistrationForm(request.POST or None, request.FILES or None)
    if request.method == 'POST' and form.is_valid():
        with transaction.atomic():
            password = form.cleaned_data['password']
            user = CustomUser.objects.create_user(
                username=form.cleaned_data['email'],
                email=form.cleaned_data['email'],
                first_name=form.cleaned_data['full_name'].split(' ')[0] if ' ' in form.cleaned_data['full_name'] else form.cleaned_data['full_name'],
                last_name=form.cleaned_data['full_name'].split(' ')[-1] if ' ' in form.cleaned_data['full_name'] else '',
                role='patient',
                password=password
            )
            user.save()
            PatientProfile.objects.create(
                user=user,
                date_of_birth=form.cleaned_data['dob'],
                gender=form.cleaned_data['gender'],
                blood_group=form.cleaned_data['blood_group'],
                contact_number=form.cleaned_data['phone'],
                medical_history=form.cleaned_data['medical_conditions'],
                emergency_contact_name=form.cleaned_data['emergency_name'],
                emergency_contact_relationship=form.cleaned_data['relationship'],
                emergency_contact_phone=form.cleaned_data['emergency_phone'],
                profile_picture=form.cleaned_data['profile_pic'] if form.cleaned_data['profile_pic'] else None,
                doctor=form.cleaned_data['doctor']
            )
            login(request, user)
            return redirect('patient_dashboard')
    return render(request, 'registration/patient_register.html', {'form': form})
