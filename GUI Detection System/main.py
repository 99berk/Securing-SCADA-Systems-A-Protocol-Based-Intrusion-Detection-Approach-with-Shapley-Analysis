import tkinter as tk
from tkinter import filedialog
import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, classification_report, precision_score, recall_score, f1_score, \
    brier_score_loss
from sklearn.preprocessing import LabelEncoder

import dpkt
import csv
from socket import inet_ntoa
from scapy.all import *
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP
from scapy.all import Raw
from scapy.layers.dns import DNS, IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.contrib.igmpv3 import IGMPv3

is_calculating = False

is_converting = False


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


def pcap_to_csv(attack_pcap_file_entry, normal_pcap_file_entry, condition_text):
    global is_converting
    if is_converting:
        condition_text.insert(tk.END, "Please Wait, Converting Not Finished Yet...\n")
        return

    is_converting = True

    attack_pcap_file = attack_pcap_file_entry.get()
    normal_pcap_file = normal_pcap_file_entry.get()

    if not attack_pcap_file or not normal_pcap_file:
        condition_text.insert(tk.END, "Please select both files.\n", "error")
        is_converting = False
        return

    directory_1 = os.path.dirname(attack_pcap_file)
    directory_2 = os.path.dirname(normal_pcap_file)

    condition_text.delete(1.0, tk.END)
    condition_text.insert(tk.END, "Please Wait, Converting...\n")

    tasks = [
        (extract_modbus_data, attack_pcap_file, os.path.join(directory_1, "attack_modbus.csv")),
        (extract_modbus_data, normal_pcap_file, os.path.join(directory_2, "benign_modbus.csv")),
        (extract_tcp_data, attack_pcap_file, os.path.join(directory_1, "attack_tcp.csv")),
        (extract_tcp_data, normal_pcap_file, os.path.join(directory_2, "benign_tcp.csv"))
    ]

    for func, pcap_file, output_file in tasks:
        thread = threading.Thread(target=func, args=(pcap_file, output_file))
        thread.start()
        thread.join()

    condition_text.insert(tk.END, "Conversion finished.\n")
    is_converting = False


def evaluate_model(X_train, X_test, y_train, y_test, grid_search, result_text):
    grid_search.fit(X_train, y_train)
    model = grid_search.best_estimator_
    y_pred = model.predict(X_test)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, str(model) + "\n")
    result_text.insert(tk.END, "Model Performance:\n")
    result_text.insert(tk.END, "Accuracy: " + str(accuracy_score(y_test, y_pred)) + "\n")
    result_text.insert(tk.END, "Precision: " + str(precision_score(y_test, y_pred)) + "\n")
    result_text.insert(tk.END, "Recall: " + str(recall_score(y_test, y_pred)) + "\n")
    result_text.insert(tk.END, "F1-Score: " + str(f1_score(y_test, y_pred)) + "\n")
    result_text.insert(tk.END, "Brier Score Loss: " + str(brier_score_loss(y_test, y_pred)) + "\n")
    result_text.insert(tk.END, "\nClassification Report:\n")
    result_text.insert(tk.END, classification_report(y_test, y_pred) + "\n")
    result_text.insert(tk.END, '-'*50 + "\n")
    global is_calculating
    is_calculating = False


def load_data(filename, protocol):
    try:
        data = pd.read_csv(filename)
        if protocol == "TCP":
            encoder = LabelEncoder()
            data['Flags_encoded'] = encoder.fit_transform(data['Flags'])
            selected_features = ['Length', 'SrcPkt', 'SrcBytes', 'DstPkt', 'Sport', 'Dport', 'IP_id', 'Sequence',
                                 'Acknowledgment', 'Window', 'Flags_encoded']
        elif protocol == "Modbus":
            selected_features = ['Transaction_ID', 'Protocol_ID', 'Length', 'Unit_ID', 'Function_Code', 'Ip_id',
                                 'Sport', 'Chksum']
        else:
            raise ValueError("Invalid protocol specified")
        return data[selected_features]
    except Exception as e:
        raise e


def browse_file_1(entry):
    filename = filedialog.askopenfilename(filetypes=(("PCAP files", "*.pcap"), ("All files", "*.*")))
    entry.delete(0, tk.END)
    entry.insert(0, filename)


def browse_file(entry, protocol_var):
    filename = filedialog.askopenfilename(filetypes=(("CSV files", "*.csv"), ("All files", "*.*")))
    entry.delete(0, tk.END)
    entry.insert(0, filename)

    if not filename:
        return 0

    if "/" in filename:
        filename_parts = filename.split("/")
        filename_f = filename_parts[-1]

    if "Modbus" in filename_f or "modbus" in filename_f or "MODBUS" in filename_f:
        protocol_var.set("Modbus")
    elif "TCP" in filename_f or "tcp" in filename_f or "Tcp" in filename_f:
        protocol_var.set("TCP")


def run_evaluation(model, param_grid, attack_file_entry, normal_file_entry, result_text, protocol):
    global is_calculating
    if is_calculating:
        result_text.insert(tk.END, "Please Wait, Calculation Not Finished Yet...\n")
        return

    is_calculating = True

    attack_file = attack_file_entry.get()
    normal_file = normal_file_entry.get()

    if not attack_file or not normal_file:
        result_text.insert(tk.END, "Please select both files.\n", "error")
        is_calculating = False
        return

    try:
        attack_data = load_data(attack_file, protocol)
        benign_data = load_data(normal_file, protocol)
    except Exception as e:
        result_text.insert(tk.END, f"Error loading data: {str(e)}\n", "error")
        is_calculating = False
        return

    attack_data['Label'] = 1
    benign_data['Label'] = 0

    merged_data = pd.concat([attack_data, benign_data]).sample(frac=1, random_state=42).reset_index(drop=True)

    selected_features = merged_data.columns.tolist()
    selected_features.remove('Label')

    X = merged_data[selected_features]
    y = merged_data['Label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, "Please Wait, Calculating...\n")

    grid_search = GridSearchCV(model, param_grid, cv=5)
    threading.Thread(target=evaluate_model, args=(X_train, X_test, y_train, y_test, grid_search, result_text)).start()


def create_ui():
    root = tk.Tk()
    root.title("SCADA Detection System")

    title_label = tk.Label(root, text="SCADA Attack Detection System", font=("Arial", 16, "bold"), pady=10)
    title_label.grid(row=0, column=0, columnspan=3)

    def on_closing():
        root.destroy()
        exit()

    root.protocol("WM_DELETE_WINDOW", on_closing)

    protocol_var = tk.StringVar()
    protocol_var.set("TCP")

#
    attack_pcap_file_label = tk.Label(root, text="Attack Pcap File:")
    attack_pcap_file_label.grid(row=1, column=0)

    attack_pcap_file_entry = tk.Entry(root, width=50)
    attack_pcap_file_entry.grid(row=1, column=1)

    attack_pcap_file_button = tk.Button(root, text="Browse", command=lambda: browse_file_1(attack_pcap_file_entry))
    attack_pcap_file_button.grid(row=1, column=2)
#

#
    normal_pcap_file_label = tk.Label(root, text="Normal Pcap File:")
    normal_pcap_file_label.grid(row=2, column=0)

    normal_pcap_file_entry = tk.Entry(root, width=50)
    normal_pcap_file_entry.grid(row=2, column=1)

    normal_pcap_file_button = tk.Button(root, text="Browse", command=lambda: browse_file_1(normal_pcap_file_entry))
    normal_pcap_file_button.grid(row=2, column=2)
#

#
    condition_text = tk.Text(root, height=2, width=80)
    condition_text.grid(row=4, columnspan=3)
    condition_text.bind("<Key>", "break")
#

#
    convert_pcap_file_button = tk.Button(root, text="Convert to CSV File", command=lambda: pcap_to_csv(attack_pcap_file_entry, normal_pcap_file_entry, condition_text))
    convert_pcap_file_button.grid(row=3, column=1)
#

    attack_file_label = tk.Label(root, text="Attack CSV File:")
    attack_file_label.grid(row=5, column=0)

    attack_file_entry = tk.Entry(root, width=50)
    attack_file_entry.grid(row=5, column=1)

    attack_file_button = tk.Button(root, text="Browse", command=lambda: browse_file(attack_file_entry, protocol_var))
    attack_file_button.grid(row=5, column=2)

    normal_file_label = tk.Label(root, text="Normal CSV File:")
    normal_file_label.grid(row=6, column=0)

    normal_file_entry = tk.Entry(root, width=50)
    normal_file_entry.grid(row=6, column=1)

    normal_file_button = tk.Button(root, text="Browse", command=lambda: browse_file(normal_file_entry, protocol_var))
    normal_file_button.grid(row=6, column=2)

    protocol_label = tk.Label(root, text="Protocol:")
    protocol_label.grid(row=7, column=0)

    protocol_menu = tk.OptionMenu(root, protocol_var, "TCP", "Modbus", "RMI", "ARP", "MDNS")
    protocol_menu.grid(row=7, column=1)

    result_text = tk.Text(root, height=20, width=80)
    result_text.grid(row=9, columnspan=3)
    result_text.bind("<Key>", "break")

    result_text.tag_config("error", foreground="red")

    evaluate_rf_button = tk.Button(root, text="Evaluate Random Forest",
                                   command=lambda: run_evaluation(RandomForestClassifier(), rf_param_grid,
                                                                  attack_file_entry, normal_file_entry, result_text,
                                                                  protocol_var.get()))
    evaluate_rf_button.grid(row=8, column=0)

    evaluate_dt_button = tk.Button(root, text="Evaluate Decision Tree",
                                   command=lambda: run_evaluation(DecisionTreeClassifier(), dt_param_grid,
                                                                  attack_file_entry, normal_file_entry, result_text,
                                                                  protocol_var.get()))
    evaluate_dt_button.grid(row=8, column=1)

    evaluate_mlp_button = tk.Button(root, text="Evaluate MLP",
                                    command=lambda: run_evaluation(MLPClassifier(), mlp_param_grid, attack_file_entry,
                                                                   normal_file_entry, result_text, protocol_var.get()))
    evaluate_mlp_button.grid(row=8, column=2)

    root.mainloop()


if __name__ == "__main__":
    rf_param_grid = {'n_estimators': [10, 50, 100], 'max_features': ['auto', 'sqrt', 'log2']}
    dt_param_grid = {'criterion': ['gini', 'entropy'], 'max_depth': [None, 10, 20, 30]}
    mlp_param_grid = {'hidden_layer_sizes': [(50, 50, 50), (50, 100, 50), (100,)],
                      'activation': ['tanh', 'relu'], 'solver': ['sgd', 'adam'],
                      'alpha': [0.0001, 0.05], 'learning_rate': ['constant', 'adaptive']}

    create_ui()
