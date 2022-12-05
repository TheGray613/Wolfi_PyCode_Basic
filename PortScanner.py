import socket, sys, os
#os system("clear")

host = "shodan.io"
ip = socket.gethostbyname(host)
open_ports = []
start_port = 79
end_port= 82
def probe_port(host, port, result = 1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        r = sock.connect_ex((host, port))
        if r == 0:
            result = r
            sock.close()
            except Exception as e:
                pass
            ruturn result
    for p in range (start_port, end_port+1):
        sys.stdout.flush()
        print(p)
    responce = probe_port(host, p)
    if responce == 0:
        open_ports.append(p)
    if not p == end_port:
        sys.stdout.write("\b" * len(str(p)))
    if open_ports:
        print("THe port is open,staty hacking buddy and enjoy it")
        print(sorted(open_ports))
    else:
        print("I can not found any open port and you Waste you're time")