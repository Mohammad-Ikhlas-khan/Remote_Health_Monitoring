# medidash/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, DoctorProfile, PatientProfile, Device, VitalSign, MedicalRecord, Alert, Report, Message, SystemNotification

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (
        (('Roles', {'fields': ('role',)}),)
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        (('Roles', {'fields': ('role',)}),)
    )
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'role')
    list_filter = ('role', 'is_staff', 'is_active')

admin.site.register(DoctorProfile)
admin.site.register(PatientProfile)
admin.site.register(Device)
admin.site.register(VitalSign)
admin.site.register(MedicalRecord)
admin.site.register(Alert)
admin.site.register(Report)
admin.site.register(Message)
admin.site.register(SystemNotification)