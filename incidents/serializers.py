from rest_framework import serializers

from incidents.models import Incident, Employee


class IncidentSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Incident
        fields = ["information"]


class IncidentSummarySerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Incident
        fields = ["employee.id", "low_priority_count"]


class EmployeeSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Employee
        fields = ["id", "source_ip"]
