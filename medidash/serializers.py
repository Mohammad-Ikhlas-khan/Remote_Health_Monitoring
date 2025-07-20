from rest_framework import serializers
from .models import VitalSign
 
class VitalSignSerializer(serializers.ModelSerializer):
    class Meta:
        model = VitalSign
        fields = ['id', 'patient', 'recorded_by_device', 'timestamp', 'vital_type', 'value', 'unit', 'status']
        read_only_fields = ['id', 'timestamp', 'patient'] 