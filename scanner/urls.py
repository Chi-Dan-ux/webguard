from django.urls import path
from . import views

urlpatterns = [
    path('start/', views.start_scan, name='start_scan'),
    path('results/<int:scan_id>/', views.scan_results, name='scan_results'),
    path('dashboard-data/', views.get_dashboard_data, name='dashboard_data'),
    path('all/', views.all_scans, name='all_scans'),
    path('executive/<int:scan_id>/', views.executive_summary, name='executive_summary'),
    path('pdf/<int:scan_id>/<str:report_type>/', views.download_pdf, name='download_pdf'),
    path('org-summary/', views.org_risk_summary, name='org_risk_summary'),
]