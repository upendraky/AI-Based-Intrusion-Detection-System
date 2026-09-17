import requests
import pandas as pd
import numpy as np


# Dataset
DATASET = "data/raw/cicids_ddos.csv"

# Load dataset
df = pd.read_csv(DATASET)

# Clean column names
df.columns = df.columns.str.strip()

# Replace infinite values
df = df.replace([np.inf, -np.inf], np.nan)

# Remove rows containing NaN
df = df.dropna()

# Remove identifiers
columns_to_drop = [
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Timestamp"
]

df = df.drop(
    columns=[col for col in columns_to_drop if col in df.columns],
    errors="ignore"
)


# ============================================================
# TEST BENIGN TRAFFIC
# ============================================================

benign_row = df[df["Label"] == "BENIGN"].iloc[0]

benign_features = benign_row.drop("Label").to_dict()

response = requests.post(
    "http://localhost:8000/api/predict",
    json={
        "features": benign_features
    }
)

print("\n==============================")
print("BENIGN TRAFFIC TEST")
print("==============================")

print("HTTP Status:", response.status_code)
print("Response:", response.json())


# ============================================================
# TEST DDOS TRAFFIC
# ============================================================

ddos_row = df[df["Label"] == "DDoS"].iloc[0]

ddos_features = ddos_row.drop("Label").to_dict()

response = requests.post(
    "http://localhost:8000/api/predict",
    json={
        "features": ddos_features
    }
)

print("\n==============================")
print("DDoS TRAFFIC TEST")
print("==============================")

print("HTTP Status:", response.status_code)
print("Response:", response.json())
