import pyshark
import logging
import time

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def test_pyshark_initialization(pcap_file):
    logging.info(f"Testing pyshark initialization with {pcap_file}")
    try:
        start_time = time.time()
        capture = pyshark.FileCapture(pcap_file, tshark_path='/usr/bin/tshark')
        packet_count = 0
        for packet in capture:
            packet_count += 1
            if packet_count % 100 == 0:
                logging.info(f"Processed {packet_count} packets so far")
            if time.time() - start_time > 30:
                logging.warning("Timeout reached, stopping capture")
                break
        logging.info(f"Total packets processed: {packet_count}")
        capture.close()
    except Exception as e:
        logging.error(f"Error initializing pyshark: {e}")

pcap_file = 'cicids2017/Monday-WorkingHours.pcap'
test_pyshark_initialization(pcap_file)
