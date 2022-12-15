import pyfiglet #The Pyfiglet module is specially designed to enhance our programming experience as well as to enhance the overall look and structure of the texts used in electronic communication. The pyfiglet module of Python works on the Figlet method, which was originally designed for the C, and later it was imported into Python.
import sys
import socket
from datetime import datetime

#In these 3 line you will find MAGIC ! when i used mataspoloit find many code look this one with same appearance(why ???)because we want user feeling better exprience.
ascii_banner = pyfiglet.figlet_format("WELCOME TO WOLFI PORT SCANNER")
print(ascii_banner)
  

# Defining a target
if len(sys.argv) == 2:
     
    # translate hostname to IPv4
    target = socket.gethostbyname(sys.argv[1])
else:
    print("Invalid amount of Argument")

# print("-" * 50) ......> you will have 50 - for seprate line and better view !
# Add Banner
print("-" * 50)
print("Scanning Target: " + target)
print("Scanning started at:" + str(datetime.now()))
print("-" * 50)
  
try:
     
    # will scan ports between 1 to 65,535
    # 65535 is all of the ports ! 
    for port in range(1,65535):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
         
        # returns an error indicator
        result = s.connect_ex((target,port))
        if result ==0:
            print("Port {} is open".format(port))
        s.close()
         
except KeyboardInterrupt:
        print("\n Exiting Program !!!!")
        sys.exit()
except socket.gaierror:
        print("\n Hostname Could Not Be Resolved !!!!")
        sys.exit()
except socket.error:
        print("\ Server not responding !!!!")
        sys.exit()

#With this command in cmd you will run it E:>LightPortS canner.py google.com