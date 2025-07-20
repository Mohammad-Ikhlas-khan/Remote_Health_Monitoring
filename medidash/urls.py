# medidash/urls.py

from django.urls import path
from . import views

urlpatterns = [
    # IMPORTAfNT: This line ensures that the root URL ('') maps to user_login.
    # It should be the first entry in this list if this app is included at the project's root.
    path('', views.user_login, name='home'), # Maps root to login/role-based redirect
    
    # Authentication URLs
    path('login/', views.user_login, name='login'), # Keep explicit login path
    path('access-denied/', views.access_denied, name='access_denied'),
    path('logout/', views.user_logout, name='logout'),
    path('forget-password/', views.forget_password, name='forget_password'),
    path('password_reset_done/', views.password_reset_done, name='password_reset_done'),
    path('password_reset_confirm/<uidb64>/<token>/', views.password_reset_confirm, name='password_reset_confirm'),
    path('password_reset_complete/', views.password_reset_complete, name='password_reset_complete'),
    
    # Doctor URLs
    path('doctor-dashboard/', views.doctor_dashboard, name='doctor_dashboard'),
    path('doctor-patients/', views.doctor_patients_list, name='doctor_patients_list'),
    path('doctor-patient/<int:patient_id>/', views.doctor_patient_detail, name='doctor_patient_detail'),
    path('doctor-alerts/', views.doctor_alerts, name='doctor_alerts'),
    path('doctor-reports/', views.doctor_reports, name='doctor_reports'),
    path('doctor-notifications/', views.doctor_notifications, name='doctor_notifications'),
    path('doctor-settings/', views.doctor_settings, name='doctor_settings'),
    path('doctor/messages/<int:patient_id>/', views.doctor_patient_message, name='doctor_patient_message'),
    path('doctor/add-medical-record/<int:patient_id>/', views.add_medical_record, name='add_medical_record'),
    path('doctor/change-password/', views.doctor_change_password, name='doctor_change_password'),
    path('doctor/enable-2fa/', views.doctor_enable_2fa, name='doctor_enable_2fa'),
    path('doctor/delete-account/', views.doctor_delete_account, name='doctor_delete_account'),

    # Patient URLs
    path('patient-dashboard/', views.patient_dashboard, name='patient_dashboard'),
    path('patient-vitals-history/', views.patient_vitals_history, name='patient_vitals_history'),
    path('patient-health-records/', views.patient_health_records, name='patient_health_records'),
    path('patient-messages/', views.patient_messages, name='patient_messages'),
    path('patient-notifications/', views.patient_notifications, name='patient_notifications'),
    path('patient-profile/', views.patient_profile, name='patient_profile'),
    path('patient-mark-message-read/', views.mark_message_read, name='mark_message_read'),
    path('register/', views.patient_register, name='patient_register'),
    
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin-register-user/', views.admin_register_user, name='admin_register_user'),
    path('admin-register-device/', views.admin_register_device, name='admin_register_device'),
    path('admin-view-records/', views.admin_view_records, name='admin_view_records'),
    path('admin-notifications/', views.admin_notifications, name='admin_notifications'),
    path('admin-settings/', views.admin_settings, name='admin_settings'),
    path('admin-doctor-details/<int:doctor_id>/', views.admin_doctor_details, name='admin_doctor_details'),
    path('admin-patient-details/<int:patient_id>/', views.admin_patient_details, name='admin_patient_details'),
    path('admin-edit-doctor/<int:doctor_id>/', views.admin_edit_doctor, name='admin_edit_doctor'),
    path('admin-edit-patient/<int:patient_id>/', views.admin_edit_patient, name='admin_edit_patient'),
    path('device/<uuid:device_id>/', views.device_detail, name='device_detail'),
    path('edit-emergency-info/<int:patient_id>/', views.edit_emergency_info, name='edit_emergency_info'),
    path('upload-health-record/', views.upload_health_record, name='upload_health_record'),
    path('api/esp32/vital/', views.esp32_vital_upload, name='esp32_vital_upload'),
    path('admin-delete-device/<uuid:device_id>/', views.admin_delete_device, name='admin_delete_device'),
    path('admin-delete-patient/<int:patient_id>/', views.admin_delete_patient, name='admin_delete_patient'),
    path('admin-delete-doctor/<int:doctor_id>/', views.admin_delete_doctor, name='admin_delete_doctor'),
]
