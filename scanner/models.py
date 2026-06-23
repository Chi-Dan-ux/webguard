from django.db import models
from django.contrib.auth.models import User

class Target(models.Model):
    url = models.URLField(max_length=500)
    name = models.CharField(max_length=200)
    target_type = models.CharField(max_length=50, choices=[
        ('student_portal', 'Student Portal'),
        ('lms', 'Learning Management System'),
        ('admin', 'Admin Dashboard'),
        ('other', 'Other'),
    ])
    added_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url


class Scan(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    started_by = models.ForeignKey(User, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    security_score = models.IntegerField(default=0)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Scan of {self.target.url} - {self.status}"


class Vulnerability(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('in_review', 'In Review'),
        ('patching', 'Patching'),
        ('resolved', 'Resolved'),
    ]
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='vulnerabilities')
    name = models.CharField(max_length=200)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    owasp_category = models.CharField(max_length=20)
    affected_url = models.URLField(max_length=500)
    evidence = models.TextField(blank=True)
    recommendation = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    discovered_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.severity.upper()} - {self.name}"


class Report(models.Model):
    scan = models.OneToOneField(Scan, on_delete=models.CASCADE)
    generated_at = models.DateTimeField(auto_now_add=True)
    total_vulnerabilities = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)

    def __str__(self):
        return f"Report for {self.scan}"