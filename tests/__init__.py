import pyshark
pcap_file = 'resources/sample.pcap'
pcap = pyshark.FileCapture(pcap_file)

for packet in pcap:
    first_packet = packet
    break
