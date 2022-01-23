from scapy.all import*
def arpmon(pkt):
    if arp in pkt :
        #hw = hardware
    return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")
    snif(prn=arpmon, filter="arp", store=0)