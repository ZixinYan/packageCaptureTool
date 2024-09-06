"""
URL configuration for tool project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from app01 import views
urlpatterns = [
    path('admin/', admin.site.urls),
    path('tool/',views.tool),
    #information
    path('tool/information/',views.information),
    #datalink_type
    path('tool/datalinkType',views.datalink_type),
    #ip capture
    path('tool/ip_running/',views.ip_capture_packets),
    path('tool/ip/',views.ip),
    path('tool/ip/download_pcap/', views.download_pcap, name='download_pcap'),
    #All packet capture
    path('tool/all_running/',views.all_capture_packets),
    path('tool/all/', views.All),
    path('tool/all/download_pcap/', views.download_pcap,name='download_pcap'),
    #Ethernet capture
    path('tool/ether_running/', views.ether_capture_packets),
    path('tool/ether/', views.ether),
    path('tool/ether/download_pcap/', views.download_pcap, name='download_pcap'),
    #ARP capture
    path('tool/arp_running/', views.arp_capture_packets),
    path('tool/arp/', views.arp),
    path('tool/arp/download_pcap/', views.download_pcap, name='download_pcap'),
    #TCP capture
    path('tool/tcp_running/', views.tcp_capture_packets),
    path('tool/tcp/', views.tcp),
    path('tool/tcp/download_pcap/', views.download_pcap, name='download_pcap'),
    #UDP capture
    path('tool/udp_running/', views.udp_capture_packets),
    path('tool/udp/', views.udp),
    path('tool/udp/download_pcap/', views.download_pcap, name='download_pcap'),
    #ICMP capture
    path('tool/icmp_running/', views.icmp_capture_packets),
    path('tool/icmp/', views.icmp),
    path('tool/icmp/download_pcap/', views.download_pcap, name='download_pcap'),
]
