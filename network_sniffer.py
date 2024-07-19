from scapy.all import sniff, wrpcap

def sniffing(packet):
    print(packet.summary())
    packets.append(packet)
packets=[]

capture=[]

capture=sniff(prn=sniffing,count=20,filter="tcp")

wrpcap("sniffing1.pcap", packets)
 