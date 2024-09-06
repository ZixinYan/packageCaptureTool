from django.shortcuts import render,HttpResponse
import subprocess
from django.http import JsonResponse, HttpResponseRedirect,FileResponse
import asyncio
import json
from django.utils.html import escape
# Create your views here.
def tool(request):
	return render(request,"tool.html")
def download_pcap(request):
	file_path = 'captured_packets.pcap'
	response = FileResponse(open(file_path, 'rb'), as_attachment=True, filename='captured_packets.pcap')
	return response

def information(request):
	subprocess.run(['./gain_Information'],capture_output=True,text=True)
	with open('information.txt', 'r') as file:
		output = file.read()
	html_output = escape(output).replace('\n', '<br>')
	return HttpResponse(html_output)
	#return render(request,"information.html",{"output":output})

def datalink_type(request):
	device = request.GET.get('device')
	subprocess.run(['sudo','./datalink_type',device],capture_output=True,text=True)
	with open('datalink_type.txt', 'r') as file:
		output = file.read()
	html_output = escape(output).replace('\n', '<br>')
	return HttpResponse(html_output)


from scapy.all import rdpcap, ARP, UDP, TCP, ICMP, Ether,IP


async def run_capture(command):
	process = await asyncio.create_subprocess_exec(
        *command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
	stdout, stderr = await process.communicate()
	return stdout, stderr

async def ip_capture_packets(request):
	#device = 'ens160'
	#num_packets = 10
	device = request.GET.get('device')
	num_packets = request.GET.get('num_packets')
	if device and num_packets:
		stdout, stderr = await run_capture(['sudo', './IP_Packets', device, str(num_packets)])
		if stderr:
			return JsonResponse({'error': stderr.decode()})
	return HttpResponseRedirect('/tool/ip/')

def ip(request):
	packets = rdpcap('captured_packets.pcap')
	packet_info = []
	for packet in packets:
		if IP in packet:
			packet_info.append({
    	        'src': packet[IP].src,
                'dst': packet[IP].dst,
                'protocol': packet[IP].proto if hasattr(packet[IP], 'proto') else 'N/A',
                'length': len(packet)
            })
	return render(request, 'packets.html', {'packets': packet_info, 'title': 'IP'})

async def udp_capture_packets(request):
	device = request.GET.get('device')
	num_packets = request.GET.get('num_packets')
	if device and num_packets:
		stdout, stderr = await run_capture(['sudo', './UDP_Packets', device, str(num_packets)])
		if stderr:
			return JsonResponse({'error': stderr.decode()})
	return HttpResponseRedirect('/tool/udp/')

def udp(request):
	packets = rdpcap('captured_packets.pcap')
	packet_info = []
	for packet in packets:
		if UDP in packet:
			packet_info.append({
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'protocol': 'UDP',
                'length': len(packet)
            })
	return render(request, 'packets.html', {'packets': packet_info, 'title': 'UDP'})

async def tcp_capture_packets(request):
	device = request.GET.get('device')
	num_packets = request.GET.get('num_packets')
	if device and num_packets:
		stdout, stderr = await run_capture(['sudo', './TCP_Packets', device, str(num_packets)])
		if stderr:
			return JsonResponse({'error': stderr.decode()})
	return HttpResponseRedirect('/tool/tcp/')

def tcp(request):
	packets = rdpcap('captured_packets.pcap')
	packet_info = []
	for packet in packets:
		if TCP in packet:
			packet_info.append({
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'protocol': 'TCP',
                'length': len(packet)
            })
	return render(request, 'packets.html', {'packets': packet_info, 'title': 'TCP'})

async def icmp_capture_packets(request):
	device = request.GET.get('device')
	num_packets = request.GET.get('num_packets')
	if device and num_packets:
		stdout, stderr = await run_capture(['sudo', './ICMP_Packets', device, str(num_packets)])
		if stderr:
			return JsonResponse({'error': stderr.decode()})
	return HttpResponseRedirect('/tool/icmp/')

def icmp(request):
	packets = rdpcap('captured_packets.pcap')
	packet_info = []
	for packet in packets:
		if ICMP in packet:
			packet_info.append({
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'protocol': 'ICMP',
                'length': len(packet)
            })
	return render(request, 'packets.html', {'packets': packet_info, 'title': 'ICMP'})

async def arp_capture_packets(request):
	device = request.GET.get('device')
	num_packets = request.GET.get('num_packets')
	if device and num_packets:
		stdout, stderr = await run_capture(['sudo', './ARP_Packets', device, str(num_packets)])
		if stderr:
			return JsonResponse({'error': stderr.decode()})
	return HttpResponseRedirect('/tool/arp/')

def arp(request):
	packets = rdpcap('captured_packets.pcap')
	packet_info = []
	for packet in packets:
		if ARP in packet:
			arp_layer = packet[ARP]
			src_ip = arp_layer.psrc
			dst_ip = arp_layer.pdst
			hwsrc = arp_layer.hwsrc
			hwdst = arp_layer.hwdst

			packet_info.append({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'hwsrc': hwsrc,
                'hwdst': hwdst,
                'length': len(packet)
            })
	return render(request, 'arp_packets.html', {'packets': packet_info, 'title': 'ARP'})

async def ether_capture_packets(request):
	device = request.GET.get('device')
	num_packets = request.GET.get('num_packets')
	if device and num_packets:
		stdout, stderr = await run_capture(['sudo', './Ethernet_Packets', device, str(num_packets)])
		if stderr:
			return JsonResponse({'error': stderr.decode()})
	return HttpResponseRedirect('/tool/ether/')

def ether(request):
	packets = rdpcap('captured_packets.pcap')
	packet_info = []
	for packet in packets:
		if Ether in packet:
			packet_info.append({
                'src': packet[Ether].src,
                'dst': packet[Ether].dst,
                'protocol': 'Ethernet',
                'length': len(packet)
            })
	return render(request, 'packets.html', {'packets': packet_info, 'title': 'Ethernet'})

async def all_capture_packets(request):
	device = request.GET.get('device')
	num_packets = request.GET.get('num_packets')
	stdout, stderr = await run_capture(['sudo', './ALL_Packets', device, str(num_packets)])
	if stderr:
			return JsonResponse({'error': stderr.decode()})
	return HttpResponseRedirect('/tool/all/')

def All(request):
	packets = rdpcap('captured_packets.pcap')
	packet_info = []
	for packet in packets:
		packet_info.append({
            'src': packet[IP].src if IP in packet else 'N/A',
            'dst': packet[IP].dst if IP in packet else 'N/A',
            'protocol': packet[IP].proto if IP in packet and hasattr(packet[IP], 'proto') else 'N/A',
            'length': len(packet)
        })
	return render(request, 'packets.html', {'packets': packet_info, 'title': '数据包'})



