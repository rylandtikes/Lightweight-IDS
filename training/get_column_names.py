import pandas as pd
dataset_path = 'processed_data_subset.csv'
df = pd.read_csv(dataset_path)
print(df.columns)
