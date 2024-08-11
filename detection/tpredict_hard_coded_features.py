import pyshark
import pandas as pd
import joblib
import logging

logging.basicConfig(level=logging.DEBUG, 
                    handlers=[
                        logging.FileHandler("log/attack_alerts.log"),
                        logging.StreamHandler()
                    ])
logger = logging.getLogger(__name__)

logging.getLogger('numba').setLevel(logging.WARNING)

rf_model = joblib.load('models/rf_model_cuml.pkl')
knn_model = joblib.load('models/knn_model_cuml.pkl')
scaler = joblib.load('models/scaler.pkl')

expected_features = [
    'Init_Win_bytes_forward', 'Destination Port', 'Packet Length Variance', 
    'Average Packet Size', 'Packet Length Std', 'Max Packet Length', 
    'Subflow Fwd Bytes', 'Bwd Packet Length Max', 'Fwd Packet Length Mean', 
    'Bwd Packet Length Mean', 'Fwd Packet Length Min', 'Bwd Packet Length Std', 
    'Bwd Packet Length Min', 'Init_Win_bytes_backward', 'Fwd Packet Length Std', 
    'Packet Length Mean', 'Fwd Header Length', 'Fwd Packet Length Max', 
    'Fwd Header Length.1', 'Bwd Header Length'
]

def generate_realtime_dataset_from_pcap(pcap_file):
    capture = pyshark.FileCapture(
        pcap_file, 
        tshark_path='/usr/bin/tshark', 
        keep_packets=False, 
        debug=True, 
        output_file=None, 
        override_prefs={'tcp.desegment_tcp_streams': 'false'}
    )

    data = {feature: [] for feature in expected_features}

    def append_data_to_all_columns(data_dict, value=0):
        for key in data_dict.keys():
            if len(data_dict[key]) < len(data['Destination Port']):
                data_dict[key].append(value)

    try:
        packet_count = 0
        for packet in capture:
            packet_count += 1
            logger.debug(f"Processing packet {packet_count}")

            # Extract each feature from the packet
            try:
                data['Destination Port'].append(int(packet['IP'].dst_port) if hasattr(packet, 'IP') else 0)
            except AttributeError:
                data['Destination Port'].append(0)
            try:
                data['Init_Win_bytes_forward'].append(int(packet['TCP'].window_size_value) if hasattr(packet, 'TCP') else 0)
            except AttributeError:
                data['Init_Win_bytes_forward'].append(0)
            try:
                data['Packet Length Variance'].append(float(packet.length) if hasattr(packet, 'length') else 0)
            except AttributeError:
                data['Packet Length Variance'].append(0)
            try:
                data['Average Packet Size'].append(float(packet.length) if hasattr(packet, 'length') else 0)
            except AttributeError:
                data['Average Packet Size'].append(0)
            try:
                data['Packet Length Std'].append(float(packet.length) if hasattr(packet, 'length') else 0)
            except AttributeError:
                data['Packet Length Std'].append(0)
            try:
                data['Max Packet Length'].append(float(packet.length) if hasattr(packet, 'length') else 0)
            except AttributeError:
                data['Max Packet Length'].append(0)
            try:
                data['Subflow Fwd Bytes'].append(int(packet['TCP'].window_size_value) if hasattr(packet, 'TCP') else 0)
            except AttributeError:
                data['Subflow Fwd Bytes'].append(0)
            try:
                data['Bwd Packet Length Max'].append(float(packet.length) if hasattr(packet, 'length') else 0)
            except AttributeError:
                data['Bwd Packet Length Max'].append(0)
            try:
                data['Fwd Packet Length Mean'].append(float(packet.length) if hasattr(packet, 'length') else 0)
            except AttributeError:
                data['Fwd Packet Length Mean'].append(0)
            try:
                data['Bwd Packet Length Mean'].append(float(packet.length) if hasattr(packet, 'length') else 0)
            except AttributeError:
                data['Bwd Packet Length Mean'].append(0)
            try:
                data['Fwd Packet Length Min'].append(float(packet.length) if hasattr(packet, 'length') else 0)
            except AttributeError:
                data['Fwd Packet Length Min'].append(0)
            try:
                data['Bwd Packet Length Std'].append(float(packet.length) if hasattr(packet, 'length') else 0)
            except AttributeError:
                data['Bwd Packet Length Std'].append(0)
            try:
                data['Bwd Packet Length Min'].append(float(packet.length) if hasattr(packet, 'length') else 0)
            except AttributeError:
                data['Bwd Packet Length Min'].append(0)
            try:
                data['Init_Win_bytes_backward'].append(int(packet['TCP'].window_size_value) if hasattr(packet, 'TCP') else 0)
            except AttributeError:
                data['Init_Win_bytes_backward'].append(0)
            try:
                data['Fwd Packet Length Std'].append(float(packet.length) if hasattr(packet, 'length') else 0)
            except AttributeError:
                data['Fwd Packet Length Std'].append(0)
            try:
                data['Packet Length Mean'].append(float(packet.length) if hasattr(packet, 'length') else 0)
            except AttributeError:
                data['Packet Length Mean'].append(0)
            try:
                data['Fwd Header Length'].append(int(packet['TCP'].hdr_len) if hasattr(packet, 'TCP') else 0)
            except AttributeError:
                data['Fwd Header Length'].append(0)
            try:
                data['Fwd Packet Length Max'].append(float(packet.length) if hasattr(packet, 'length') else 0)
            except AttributeError:
                data['Fwd Packet Length Max'].append(0)
            try:
                data['Fwd Header Length.1'].append(int(packet['TCP'].hdr_len) if hasattr(packet, 'TCP') else 0)
            except AttributeError:
                data['Fwd Header Length.1'].append(0)
            try:
                data['Bwd Header Length'].append(int(packet['TCP'].hdr_len) if hasattr(packet, 'TCP') else 0)
            except AttributeError:
                data['Bwd Header Length'].append(0)

            append_data_to_all_columns(data)

            if len(data['Destination Port']) > 0:
                df = pd.DataFrame(data)
                df = df.fillna(0)
                X_new = df.iloc[-1:, :]

                if X_new.shape[1] == len(expected_features):
                    X_new_scaled = scaler.transform(X_new)
                    rf_prediction = rf_model.predict(X_new_scaled)
                    knn_prediction = knn_model.predict(X_new_scaled)

                    logger.info(f"RF Prediction: {rf_prediction[-1]}, KNN Prediction: {knn_prediction[-1]}")

                    if rf_prediction[-1] == 1 or knn_prediction[-1] == 1:
                        logger.info(f"Attack detected in packet {packet_count}: RF={rf_prediction[-1]}, KNN={knn_prediction[-1]}")
                        break
                else:
                    logger.warning(f"Skipping packet {packet_count}: Insufficient features (expected {len(expected_features)}, got {X_new.shape[1]})")

    except pyshark.capture.capture.TSharkCrashException as e:
        logger.error(f"TShark crashed: {e}")
        if hasattr(e, 'last_line'):
            logger.error(f"Last error line: {e.last_line}")

pcap_file = '../training/cicids2017/Friday-WorkingHours.pcap'
generate_realtime_dataset_from_pcap(pcap_file)
