from django.db import models
from django.utils import timezone


# Create your models here.
class Employee(models.Model):
    id = models.IntegerField(primary_key=True)
    source_ip = models.TextField(null=False)


class Incident(models.Model):
    priority = models.CharField(null=False,
                                choices=[("low", "low"),
                                         ("medium", "medium"),
                                         ("high", "high"),
                                         ("critical", "critical")],
                                max_length=16)
    timestamp = models.DateTimeField(default=timezone.now)
    information = models.CharField(null=True, blank=True, max_length=128)
    employee = models.ForeignKey("Employee", on_delete=models.CASCADE, default=None)
