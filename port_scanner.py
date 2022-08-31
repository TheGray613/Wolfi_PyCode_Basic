from itertools import starmap
import socket,sys,os
# os.system('clear')
host='nooranet.com'
ip = socket.gethostbyname(host)
open_ports = []
start_port = 79
end_port = 82

def probe_port(host, port, result = 1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.sottimeout(0.5)
        r = sock.connect_ex((host, port))