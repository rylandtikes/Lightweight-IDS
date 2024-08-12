import pandas as pd
import numpy as np
from cuml.ensemble import RandomForestClassifier as cuRF
from cuml.neighbors import KNeighborsClassifier as cuKNN
from cuml.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
import joblib
import logging
import json
import cupy as cp
import sklearn.metrics as metrics 

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

CSV_FILES = [
    'cicids2017/Monday-WorkingHours.csv',
    'cicids2017/Tuesday-WorkingHours.pcap_ISCX.csv',
    'cicids2017/Wednesday-workingHours.pcap_ISCX.csv',
    'cicids2017/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    'cicids2017/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    'cicids2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'cicids2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
    'cicids2017/Friday-WorkingHours-Morning.pcap_ISCX.csv',
]

FEATURES = [
    'Init_Win_bytes_forward', 'Destination Port', 'Packet Length Variance', 'Average Packet Size',
    'Packet Length Std', 'Max Packet Length', 'Subflow Fwd Bytes', 'Bwd Packet Length Max',
    'Fwd Packet Length Mean', 'Bwd Packet Length Mean', 'Fwd Packet Length Min', 'Bwd Packet Length Std',
    'Bwd Packet Length Min', 'Init_Win_bytes_backward', 'Fwd Packet Length Std', 'Packet Length Mean',
    'Fwd Header Length', 'Fwd Packet Length Max', 'Fwd Header Length.1', 'Bwd Header Length'
]

def load_and_preprocess_data(file_paths):
    logger.info(f"Loading data from files: {file_paths}")
    
    df_list = [pd.read_csv(file_path) for file_path in file_paths]
    df = pd.concat(df_list, ignore_index=True)

    logger.info(f"Combined DataFrame shape: {df.shape}")

    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf, np.nan], -1, inplace=True)

    # Undersample the majority class
    df_majority = df[df['Label'] == 'BENIGN']
    df_minority = df[df['Label'] != 'BENIGN']

    df_majority_downsampled = df_majority.sample(n=len(df_minority), random_state=42)
    df_balanced = pd.concat([df_majority_downsampled, df_minority])

    logger.info(f"Balanced DataFrame shape: {df_balanced.shape}")

    string_features = df_balanced.select_dtypes(include=['object']).columns.tolist()
    string_features.remove('Label')
    for feature in string_features:
        df_balanced[feature] = pd.factorize(df_balanced[feature])[0]

    df_balanced['Label'] = df_balanced['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

    X = df_balanced[FEATURES]
    y = df_balanced['Label']

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Convert to CuPy arrays for GPU processing
    X_cp = cp.asarray(X_scaled)
    y_cp = cp.asarray(y.values)

    return X_cp, y_cp, scaler

def train_and_evaluate_models(X, y):
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    rf_model = cuRF(n_estimators=50, random_state=42, n_streams=1)
    knn_model = cuKNN(n_neighbors=5)

    rf_predictions = []
    knn_predictions = []
    y_tests = []

    for fold, (train_idx, test_idx) in enumerate(skf.split(X, y)):
        logger.info(f"Training fold {fold + 1}")

        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        rf_model.fit(X_train, y_train)
        rf_pred = rf_model.predict(X_test).get()
        rf_predictions.extend(rf_pred.tolist())

        knn_model.fit(X_train, y_train)
        knn_pred = knn_model.predict(X_test).get()
        knn_predictions.extend(knn_pred.tolist())

        y_tests.extend(y_test.tolist())

    rf_report = classification_report(y_tests, rf_predictions, output_dict=True)
    knn_report = classification_report(y_tests, knn_predictions, output_dict=True)

    rf_cm = confusion_matrix(y_tests, rf_predictions)
    knn_cm = confusion_matrix(y_tests, knn_predictions)

    logger.info("Random Forest Model Results:")
    print_model_metrics(y_tests, rf_predictions)
    print("Confusion Matrix:")
    print(rf_cm)

    logger.info("K-Nearest Neighbors Model Results:")
    print_model_metrics(y_tests, knn_predictions)
    print("Confusion Matrix:")
    print(knn_cm)

    with open("rf_classification_report.json", "w") as f:
        json.dump(rf_report, f, indent=4)

    with open("knn_classification_report.json", "w") as f:
        json.dump(knn_report, f, indent=4)

    with open("rf_confusion_matrix.json", "w") as f:
        json.dump(rf_cm.tolist(), f, indent=4)

    with open("knn_confusion_matrix.json", "w") as f:
        json.dump(knn_cm.tolist(), f, indent=4)

    return rf_model, knn_model

def print_model_metrics(y_true, y_pred):
    accuracy = metrics.accuracy_score(y_true, y_pred)
    precision = metrics.precision_score(y_true, y_pred)
    recall = metrics.recall_score(y_true, y_pred)
    f1 = metrics.f1_score(y_true, y_pred)
    print(f"Accuracy = {accuracy}")
    print(f"Precision = {precision}")
    print(f"Recall = {recall}")
    print(f"F1 = {f1}")

X, y, scaler = load_and_preprocess_data(CSV_FILES)
if X is not None and y is not None:
    logger.info(f"Data shape: {X.shape}, Labels shape: {y.shape}")
    rf_model, knn_model = train_and_evaluate_models(X, y)
    joblib.dump(scaler, 'scaler.pkl')
    joblib.dump(rf_model, 'rf_model_cuml.pkl')
    joblib.dump(knn_model, 'knn_model_cuml.pkl')
