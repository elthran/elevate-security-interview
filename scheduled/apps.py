import ast
import json
import time
from datetime import datetime, timezone
from threading import Thread

import requests
from django.apps import AppConfig
from django.core.exceptions import ObjectDoesNotExist
from requests.auth import HTTPBasicAuth

from elevateSecurity.settings import API_USERNAME, API_PASSWORD

base_url = "https://incident-api.use1stag.elevatesecurity.io"

# Declare constants to avoid typos or confusion
EMPLOYEE_ID = "employee_id"
SOURCE_IP = "source_ip"

# A config of each URL call, the identifying field, and which employee key to map on
incident_configs = [
    {"type": "denial", "identifier_field": "reported_by", "table_key": EMPLOYEE_ID},
    {"type": "intrusion", "identifier_field": "internal_ip", "table_key": SOURCE_IP},
    {"type": "executable", "identifier_field": "machine_ip", "table_key": SOURCE_IP},
    {"type": "misuse", "identifier_field": "employee_id", "table_key": EMPLOYEE_ID},
    {"type": "unauthorized", "identifier_field": "employee_id", "table_key": EMPLOYEE_ID},
    {"type": "probing", "identifier_field": "ip", "table_key": SOURCE_IP},
    {"type": "other", "identifier_field": "identifier", "table_key": SOURCE_IP},
]


class SchedulerThread(Thread):
    """This is our Scheduler which will run on a separate thread than the main app
    and handle pulling data on a schedule to keep the database up to date.
    It will not start running until the main app is running."""

    def run(self):
        print('Scheduler thread is running.')
        while True:
            print("Fetching employee information.")
            self.update_identities()
            print("Fetching incident information.")
            self.update_incidents()
            print(f"Updated database at {datetime.now()} UTC")
            self.save_data()
            print(f"Saved data as JSON")
            time.sleep(1200)  # Fetch data every 20 minutes

    @staticmethod
    def call_api(suffix):
        """Used to make any api calls to external urls. Returns JSON"""
        url = f"{base_url}/{suffix}/"
        response = requests.get(url, auth=HTTPBasicAuth(API_USERNAME, API_PASSWORD))
        return response.json()

    def update_identities(self):
        """Keeps an updated list of all employees and their source_ip."""
        from incidents.models import Employee
        source_ip_address_to_employee_id_mapping = self.call_api(suffix="identities")
        for source_ip, employee_id in source_ip_address_to_employee_id_mapping.items():
            try:
                employee = Employee.objects.get(id=employee_id)
                if employee.source_ip != source_ip:
                    employee.source_ip = source_ip
            except ObjectDoesNotExist:
                employee = Employee(id=employee_id, source_ip=source_ip)
                employee.clean()
                employee.save()

    def update_incidents(self):
        """We start by deleting all records in our Incidents table.
        Then for each new incident reported, we look up the Employee ID and then add the Incident to our reports."""
        from incidents.models import Employee, Incident
        Incident.objects.all().delete()
        # Cycle through our incident configs which contain the URL and parameters to pop
        for incident_config in incident_configs:
            all_incidents = self.call_api(suffix=f"incidents/{incident_config['type']}")["results"]
            for incident_data in all_incidents:
                incident_data["type"] = incident_config["type"]
                # If the incident reports the employee_id then we extract it
                if incident_config["table_key"] == EMPLOYEE_ID:
                    employee_id = incident_data.get(incident_config["identifier_field"], None)
                    employee = Employee.objects.get(id=employee_id)
                # Otherwise we look up the employee in our database
                else:
                    source_ip = incident_data.pop(incident_config["identifier_field"], None)
                    employee = Employee.objects.filter(source_ip=source_ip).first()
                priority = incident_data.get("priority", None)
                unix_timestamp = incident_data.get("timestamp", None)
                timestamp = datetime.utcfromtimestamp(unix_timestamp).replace(tzinfo=timezone.utc)
                # If the incident is missing information, we skip it for now since we can't use it
                if not employee or not priority:
                    continue
                # Create a new incident from this report and assign it to the employee_id
                incident = Incident(employee=employee,
                                    priority=priority,
                                    timestamp=timestamp,
                                    information=incident_data)
                incident.clean()
                incident.save()

    @staticmethod
    def save_data():
        """
        For quick retrieval, we will generate our report after pulling fresh data
        and save the report as a JSON file.
        """
        from incidents.models import Employee, Incident
        from incidents.serializers import IncidentSerializer
        # Initialize the JSON report
        results = {}
        # Iterate through all employees, generating a report for any that have an incident
        for employee in Employee.objects.all().order_by('id'):
            incidents = Incident.objects.filter(employee=employee).all()
            if not incidents:
                continue
            employee_incident_summary = {}
            for priority in ["low", "medium", "high", "critical"]:
                incidents = Incident.objects.filter(employee=employee, priority=priority).all()
                serializer = IncidentSerializer(incidents, many=True)
                incidents = serializer.data
                incident_dict = [ast.literal_eval(incident["information"]) for incident in incidents]
                employee_incident_summary[priority] = {"count": len(incidents),
                                                       "incidents": incident_dict}
            results[employee.id] = employee_incident_summary
        # Save the data as a JSON file
        with open('incident_report.json', 'w') as fp:
            json.dump(results, fp)


class ScheduledConfig(AppConfig):
    name = 'scheduled'

    def ready(self):
        """Ensure that the main app is running before starting this thread."""
        SchedulerThread().start()
