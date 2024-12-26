import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

data_dict = {
    "attack": {
        "TCP": r"C:...\ca_attack_tcp.csv",
        "Modbus": r"C:...\ca_attack_modbus.csv",
        "RMI": r"C:...\ca_attack_rmi.csv",
        "MDNS": r"C:...\ca_attack_mdns.csv",
        "ARP": r"C:...\ca_attack_arp.csv",
        "ICMPv6": r"C:...\ca_attack_icmpv6.csv",
        "IGMPv3": r"C:...\ca_attack_igmpv3.csv",
    },
    "benign": {
        "TCP": r"C:...\ca_benign_tcp.csv",
        "Modbus": r"C:...\ca_benign_modbus.csv",
        "RMI": r"C:...\ca_benign_rmi.csv",
        "MDNS": r"C:...\ca_benign_mdns.csv",
        "ARP": r"C:...\ca_benign_arp.csv",
        "ICMPv6": r"C:...\ca_benign_icmpv6.csv",
        "IGMPv3": r"C:...\ca_benign_igmpv3.csv",
    }
}

data_dict2 = {
    "attack": {
        "TCP": r"C:...\attack_tcp.csv",
        "Modbus": r"C:...\attack_modbus.csv",
        "RMI": r"C:...\attack_rmi.csv",
        "MDNS": r"C:...\attack_mdns.csv",
        "ARP": r"C:...\attack_arp.csv",
        "ICMPv6": r"C:...\attack_icmpv6.csv",
        "IGMPv3": r"C:...\attack_igmpv3.csv",
    },
    "benign": {
        "TCP": r"C:...\benign_tcp.csv",
        "Modbus": r"C:...\benign_modbus.csv",
        "RMI": r"C:...\benign_rmi.csv",
        "MDNS": r"C:...\benign_mdns.csv",
        "ARP": r"C:...\benign_arp.csv",
        "ICMPv6": r"C:...\benign_icmpv6.csv",
        "IGMPv3": r"C:...\benign_igmpv3.csv",
    }
}

attack_TCP_df = pd.read_csv(data_dict2["attack"]["TCP"])
benign_TCP_df = pd.read_csv(data_dict2["benign"]["TCP"])

attack_modbus_df = pd.read_csv(data_dict2["attack"]["Modbus"])
benign_modbus_df = pd.read_csv(data_dict2["benign"]["Modbus"])

class_counts = pd.DataFrame({
    'Protocols': ['TCP', 'TCP', 'Modbus', 'Modbus'],
    'Class': ['Attack', 'Benign', 'Attack', 'Benign'],
    'Count': [len(attack_TCP_df), len(benign_TCP_df), len(attack_modbus_df), len(benign_modbus_df)]
})

plt.figure(figsize=(8, 5))
bar_plot = sns.barplot(x='Protocols', y='Count', hue='Class', data=class_counts, palette=['#D32F2F', '#388E3C'])

for bar in bar_plot.patches:
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width() / 2, height + height * 0.01, f'{int(height):,}', ha='center', va='bottom', fontsize=14, fontweight='bold')

sns.despine()

plt.title('Record Counts from PCAP Files for HMI Networks', pad=25, fontsize=15, fontweight='bold')
plt.ylabel('Data Count', fontweight='bold', labelpad=10, fontsize=12)
plt.xlabel('Protocols', fontweight='bold', labelpad=5, fontsize=13)
plt.xticks(fontsize=13, fontweight='bold')

plt.show()
