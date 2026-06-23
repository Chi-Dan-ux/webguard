from django.contrib import admin
from django.urls import path, include
from accounts import views as account_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('accounts.urls')),
    path('scanner/', include('scanner.urls')),
    path('dashboard/', account_views.dashboard_view, name='dashboard'),
    path('docs/', account_views.docs_view, name='docs'),
    path('research/', account_views.research_view, name='research'),
    path('owasp/', account_views.owasp_view, name='owasp'),
    path('', account_views.landing_view, name='home'),
]