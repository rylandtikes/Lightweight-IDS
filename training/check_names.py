import pandas as pd

label_file = 'cicids2017/Monday-WorkingHours.pcap_ISCX.csv'
labels_df = pd.read_csv(label_file)
print(labels_df.columns)