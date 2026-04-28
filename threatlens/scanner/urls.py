from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('history/', views.history, name='history'),
    path('api/scan/file/', views.api_scan_file, name='api_scan_file'),
    path('api/scan/url/', views.api_scan_url, name='api_scan_url'),
    path('api/stats/', views.api_stats, name='api_stats'),
    path('api/history/', views.api_history, name='api_history'),
]
