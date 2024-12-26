import dpkt
import csv
from socket import inet_ntoa
import pandas as pd
from scapy.all import *
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP
from scapy.all import Raw
from scapy.layers.dns import DNS, IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.contrib.igmpv3 import IGMPv3


class ModBusTCP(dpkt.Packet):
    __hdr__ = (('id', 'H', 0),
               ('proto', 'H', 0),
               ('len', 'H', 0),
               ('ui', 'B', 0),
               ('fc', 'B', 0))


def extract_modbus_data(dpkt_pcap_file, output_csv):
    modbus_data = []

    with open(dpkt_pcap_file, 'rb') as pcap_file:
        pcap = dpkt.pcap.Reader(pcap_file)

        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if type(eth.data) != dpkt.ip.IP:
                continue
            ip = eth.data
            if type(ip.data) != dpkt.tcp.TCP:
                continue
            tcp = ip.data

            if (tcp.dport == 502) and len(tcp.data) > 0:
                try:
                    modtcp = ModBusTCP(tcp.data)
                    if modtcp.fc < 255 and modtcp.proto == 0:
                        modbus_data.append({
                            "No": len(modbus_data) + 1,
                            "Mean_timestamp": pd.Series(float(ts)).mean(),
                            "Source_IP": inet_ntoa(ip.src),
                            "Destination_IP": inet_ntoa(ip.dst),
                            "Transaction_ID": modtcp.id,
                            "Protocol_ID": modtcp.proto,
                            "Length": modtcp.len,
                            "Unit_ID": modtcp.ui,
                            "Function_Code": modtcp.fc,
                            "Ip_id": ip.id,
                            "Dport": tcp.dport,
                            "Sport": tcp.sport,
                            "Chksum": tcp.sum,
                        })
                except dpkt.dpkt.NeedData:
                    continue

    with open(output_csv, "w", newline="") as csvfile:
        fieldnames = ["No", "Mean_timestamp", "Source_IP", "Destination_IP",
                      "Transaction_ID", "Protocol_ID", "Length", "Unit_ID", "Function_Code",
                      "Ip_id", "Sport", "Dport", "Chksum"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()

        writer.writerows(modbus_data)


def extract_tcp_data(pcap_file, output_csv):
    fieldnames = ['No', 'Time', 'Source', 'Destination', 'IP_id', 'Sport', 'Dport', 'Length', 'SrcPkt', 'SrcBytes',
                  'DstPkt', 'Sequence', 'Acknowledgment', 'Window', 'Flags']

    packets = rdpcap(pcap_file)
    src_pkt_count = {}
    dst_pkt_count = {}
    src_bytes_count = {}

    for packet in packets:
        if 'TCP' in packet and not (
                (((packet[TCP].dport == 1099) or (packet[TCP].sport == 1099)) and (Raw in packet)) or
                (DNS in packet and packet[DNS].qr == 0) or (packet.haslayer(ARP)) or
                (IPv6 in packet and packet[IPv6].nh == 58) or (packet.haslayer(IGMPv3)) or
                (packet[TCP].flags == "PA")):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            packet_length = packet[IP].len

            src_pkt_count[(src_ip, src_port)] = src_pkt_count.get((src_ip, src_port), 0) + 1
            dst_pkt_count[(dst_ip, dst_port)] = dst_pkt_count.get((dst_ip, dst_port), 0) + 1
            src_bytes_count[(src_ip, src_port)] = src_bytes_count.get((src_ip, src_port), 0) + packet_length

    with open(output_csv, mode='w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        for i, packet in enumerate(packets):
            if 'TCP' in packet and not (
                    (((packet[TCP].dport == 1099) or (packet[TCP].sport == 1099)) and (Raw in packet)) or
                    (DNS in packet and packet[DNS].qr == 0) or (packet.haslayer(ARP)) or
                    (IPv6 in packet and packet[IPv6].nh == 58) or (packet.haslayer(IGMPv3)) or
                    (packet[TCP].flags == "PA")):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport

                writer.writerow({
                    'No': i + 1,
                    'Time': packet.time,
                    'Source': src_ip,
                    'Destination': dst_ip,
                    'IP_id': packet[IP].id,
                    'Sport': src_port,
                    'Dport': dst_port,
                    'Length': packet[IP].len,
                    'SrcPkt': src_pkt_count.get((src_ip, src_port), 0),
                    'SrcBytes': src_bytes_count.get((src_ip, src_port), 0),
                    'DstPkt': dst_pkt_count.get((dst_ip, dst_port), 0),
                    'Sequence': packet[TCP].seq,
                    'Acknowledgment': packet[TCP].ack,
                    'Window': packet[TCP].window,
                    'Flags': packet[TCP].flags
                })


def extract_rmi_data(pcap_file, output_csv):
    fieldnames = ['No', 'Time', 'Source', 'Destination', 'Length']

    with open(output_csv, mode='w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        packets = rdpcap(pcap_file)

        for i, pkt in enumerate(packets):
            if TCP in pkt and ((pkt[TCP].dport == 1099) or (pkt[TCP].sport == 1099)):
                if Raw in pkt:
                    payload = pkt[Raw].load
                    if payload:
                        writer.writerow({
                            'No': i + 1,
                            'Time': pkt.time,
                            'Source': pkt[IP].src,
                            'Destination': pkt[IP].dst,
                            'Length': len(pkt),
                        })


def extract_mdns_data(pcap_file, output_csv):
    packets = rdpcap(pcap_file)

    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['No', 'Timestamp', 'Source', 'Destination', 'MDNS Query']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for i, packet in enumerate(packets):
            if DNS in packet and packet[DNS].qr == 0:
                timestamp = packet.time

                if IP in packet:
                    source = packet[IP].src
                    destination = packet[IP].dst
                else:
                    source = packet[Ether].src
                    destination = packet[Ether].dst

                mdns_query = packet[DNS].qd.qname.decode('utf-8') if isinstance(packet[DNS].qd.qname, bytes) else \
                packet[DNS].qd.qname

                writer.writerow({
                    'No': i + 1,
                    'Timestamp': timestamp,
                    'Source': source,
                    'Destination': destination,
                    'MDNS Query': mdns_query
                })


def extract_arp_data(pcap_file, output_csv):
    fieldnames = ['No', 'Time', 'Hardware Type']

    with open(output_csv, mode='w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        packets = rdpcap(pcap_file)

        for i, pkt in enumerate(packets):
            if pkt.haslayer(ARP):
                hwtype = pkt.hwtype

                writer.writerow({
                    'No': i + 1,
                    'Time': pkt.time,
                    'Hardware Type': hwtype,
                })


def extract_icmpv6_data(pcap_file, output_csv):
    fieldnames = ['No', 'Time', 'Source', 'Destination', 'Type', 'Code', 'Payload']

    with open(output_csv, mode='w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        packets = rdpcap(pcap_file)

        for i, packet in enumerate(packets):
            if IPv6 in packet and packet[IPv6].nh == 58:
                icmpv6_type = packet[IPv6].type
                icmpv6_code = packet[IPv6].code
                payload = packet[IPv6].payload

                writer.writerow({
                    'No': i + 1,
                    'Time': packet.time,
                    'Source': packet[Ether].src,
                    'Destination': packet[Ether].dst,
                    'Type': icmpv6_type,
                    'Code': icmpv6_code,
                    'Payload': payload,
                })


def extract_igmpv3_data(pcap_file, output_csv):
    fieldnames = ['No', 'Time', 'Source', 'Destination', 'Type', 'Checksum']

    with open(output_csv, mode='w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        packets = rdpcap(pcap_file)

        for i, packet in enumerate(packets):
            if packet.haslayer(IGMPv3):
                type = packet[IGMPv3].type
                checksum = packet[IGMPv3].chksum

                writer.writerow({
                    'No': i + 1,
                    'Time': packet.time,
                    'Source': packet[IP].src,
                    'Destination': packet[IP].dst,
                    'Type': type,
                    'Checksum': checksum,
                })


if __name__ == "__main__":
    # HMI
    pcap_file_path_attack = r"C:...\veth291ab9a-0.pcap"
    pcap_file_path_benign = r"C:...\veth5bbeaa2-normal-13.pcap"

    output_csv_path_modbus_attack = r"C:...\attack_modbus.csv"
    output_csv_path_modbus_benign = r"C:...\benign_modbus.csv"
    output_csv_path_tcp_attack = r"C:...\attack_tcp.csv"
    output_csv_path_tcp_benign = r"C:...\benign_tcp.csv"
    output_csv_path_rmi_attack = r"C:...\attack_rmi.csv"
    output_csv_path_rmi_benign = r"C:...\benign_rmi.csv"
    output_csv_path_mdns_attack = r"C:...\attack_mdns.csv"
    output_csv_path_mdns_benign = r"C:...\benign_mdns.csv"
    output_csv_path_arp_attack = r"C:...\attack_arp.csv"
    output_csv_path_arp_benign = r"C:...\benign_arp.csv"
    output_csv_path_icmpv6_attack = r"C:...\attack_icmpv6.csv"
    output_csv_path_icmpv6_benign = r"C:...\benign_icmpv6.csv"
    output_csv_path_igmpv3_attack = r"C:...\attack_igmpv3.csv"
    output_csv_path_igmpv3_benign = r"C:...\benign_igmpv3.csv"

    extract_modbus_data(pcap_file_path_attack, output_csv_path_modbus_attack)
    extract_modbus_data(pcap_file_path_benign, output_csv_path_modbus_benign)
    extract_tcp_data(pcap_file_path_attack, output_csv_path_tcp_attack)
    extract_tcp_data(pcap_file_path_benign, output_csv_path_tcp_benign)
    extract_rmi_data(pcap_file_path_attack, output_csv_path_rmi_attack)
    extract_rmi_data(pcap_file_path_benign, output_csv_path_rmi_benign)
    extract_mdns_data(pcap_file_path_attack, output_csv_path_mdns_attack)
    extract_mdns_data(pcap_file_path_benign, output_csv_path_mdns_benign)
    extract_arp_data(pcap_file_path_attack, output_csv_path_arp_attack)
    extract_arp_data(pcap_file_path_benign, output_csv_path_arp_benign)
    extract_icmpv6_data(pcap_file_path_attack, output_csv_path_icmpv6_attack)
    extract_icmpv6_data(pcap_file_path_benign, output_csv_path_icmpv6_benign)
    extract_igmpv3_data(pcap_file_path_attack, output_csv_path_igmpv3_attack)
    extract_igmpv3_data(pcap_file_path_benign, output_csv_path_igmpv3_benign)
