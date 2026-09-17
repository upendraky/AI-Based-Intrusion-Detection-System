import time
import requests
import pandas as pd
import numpy as np


# ============================================================
# CONFIGURATION
# ============================================================

API_URL = "http://localhost:8000/api/predict"

DATASET_PATH = "data/raw/cicids_ddos.csv"

DELAY_SECONDS = 1

NUMBER_OF_FLOWS = 50


# ============================================================
# LOAD DATASET
# ============================================================

print("Loading CICIDS2017 dataset...")

df = pd.read_csv(DATASET_PATH)

df.columns = df.columns.str.strip()

print("Dataset loaded.")
print("Rows:", len(df))


# ============================================================
# CLEAN DATA
# ============================================================

df = df.replace(
    [np.inf, -np.inf],
    np.nan
)

df = df.dropna()

print("Rows after cleaning:", len(df))


# ============================================================
# REMOVE IDENTIFIER COLUMNS
# ============================================================

columns_to_drop = [
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Timestamp"
]

df = df.drop(
    columns=[
        column
        for column in columns_to_drop
        if column in df.columns
    ],
    errors="ignore"
)


# ============================================================
# SELECT RANDOM TRAFFIC
# ============================================================

sample = df.sample(
    n=min(NUMBER_OF_FLOWS, len(df)),
    random_state=42
)


# ============================================================
# SEND TRAFFIC
# ============================================================

print()
print("========================================")
print("Sentinel AI IDS Traffic Simulator")
print("========================================")
print()


for index, (_, row) in enumerate(sample.iterrows(), start=1):

    actual_label = row["Label"]

    features = row.drop("Label").to_dict()


    # --------------------------------------------------------
    # Send traffic to FastAPI
    # --------------------------------------------------------

    try:

        response = requests.post(
            API_URL,
            json={
                "features": features
            },
            timeout=10
        )


        if response.status_code != 200:

            print(
                f"[{index}] API ERROR:",
                response.text
            )

            continue


        result = response.json()


        # ----------------------------------------------------
        # Display result
        # ----------------------------------------------------

        print(
            f"[{index:02d}] "
            f"Actual={actual_label:<6} | "
            f"AI={result['label']:<6} | "
            f"Confidence={result['confidence']:>6.2f}% | "
            f"Threat={result['threat_score']:>6.2f} | "
            f"Severity={result['severity']}"
        )


    except requests.exceptions.RequestException as error:

        print(
            f"[{index}] Connection error:",
            error
        )

        print(
            "Make sure FastAPI is running."
        )

        break


    time.sleep(DELAY_SECONDS)


print()
print("========================================")
print("Simulation completed.")
print("========================================")
