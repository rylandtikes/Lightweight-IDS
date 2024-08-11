import pyshark
import pandas as pd
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

def process_packets(packet, labels_df, idx, data, lock):
    try:
        if idx < len(labels_df):
            row = labels_df.iloc[idx]
            with lock:
                data['frame_number'].append(packet.number)
                data['frame_len'].append(packet.length)
                data['frame_time_relative'].append(packet.sniff_time.timestamp())
                data['ip_proto'].append(packet.highest_layer)
                data['ip_src'].append(packet.ip.src if 'IP' in packet else '')
                data['ip_dst'].append(packet.ip.dst if 'IP' in packet else '')
                data['tcp_flags'].append(packet.tcp.flags if 'TCP' in packet else '')
                data['udp_length'].append(packet.udp.length if 'UDP' in packet else '')
                data['icmp_type'].append(packet.icmp.type if 'ICMP' in packet else '')
                data['label'].append(row[' Label'])
    except Exception as e:
        logger.error(f"Error processing packet {idx}: {e}")

def process_pcap(pcap_file, label_files, data, packet_count_override=None):
    try:
        capture = pyshark.FileCapture(pcap_file)
        logger.debug("Processing packets from %s", pcap_file)

        packet_count = packet_count_override if packet_count_override else 10000

        labels_dfs = [pd.read_csv(label_file) for label_file in label_files]

        lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            for idx, packet in enumerate(capture):
                if idx >= packet_count:
                    break
                for labels_df in labels_dfs:
                    futures.append(executor.submit(process_packets, packet, labels_df, idx, data, lock))
                
                if idx % 100 == 0:
                    logger.info(f"Processed {idx} packets from {pcap_file}")

            for future in as_completed(futures):
                future.result()

        capture.close()
    except Exception as e:
        logger.error(f"Error processing packets: {e}")

def main():
    pcap_files = [
        "/ml/Lightweight-IDS/cicids2017/Monday-WorkingHours.pcap",
        "/ml/Lightweight-IDS/cicids2017/Tuesday-WorkingHours.pcap",
        "/ml/Lightweight-IDS/cicids2017/Wednesday-workingHours.pcap",
        "/ml/Lightweight-IDS/cicids2017/Thursday-WorkingHours.pcap",
        "/ml/Lightweight-IDS/cicids2017/Friday-WorkingHours.pcap"
    ]
    label_files = [
        ["/ml/Lightweight-IDS/cicids2017/Monday-WorkingHours.csv"],
        ["/ml/Lightweight-IDS/cicids2017/Tuesday-WorkingHours.pcap_ISCX.csv"],
        ["/ml/Lightweight-IDS/cicids2017/Wednesday-workingHours.pcap_ISCX.csv"],
        [
            "/ml/Lightweight-IDS/cicids2017/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
            "/ml/Lightweight-IDS/cicids2017/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
        ],
        [
            "/ml/Lightweight-IDS/cicids2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
            "/ml/Lightweight-IDS/cicids2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
            "/ml/Lightweight-IDS/cicids2017/Friday-WorkingHours-Morning.pcap_ISCX.csv"
        ]
    ]

    data = {
        'frame_number': [], 'frame_len': [], 'frame_time_relative': [], 'ip_proto': [],
        'ip_src': [], 'ip_dst': [], 'tcp_flags': [], 'udp_length': [], 'icmp_type': [], 'label': []
    }
    
    for pcap_file, label_file in zip(pcap_files, label_files):
        logger.info(f"Processing {pcap_file} with labels from {label_file}")
        process_pcap(pcap_file, label_file, data, packet_count_override=10000)  # Override packet count for testing
    
    df = pd.DataFrame(data)
    logger.debug(f"Saving combined dataset with shape {df.shape}")
    df.to_csv('/ml/Lightweight-IDS/cicids2017/combined_dataset.csv', index=False)

if __name__ == "__main__":
    main()
