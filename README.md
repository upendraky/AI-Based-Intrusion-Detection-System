# AI-Based Intrusion Detection System (AI-IDS)

An AI-powered cybersecurity application that analyzes network traffic and detects potentially malicious activity using machine learning. The system combines traffic classification, feature selection, a FastAPI inference service, PostgreSQL persistence, and a monitoring dashboard to support network threat detection.

## Overview

Traditional intrusion detection systems often rely on predefined rules and signatures. This project explores a machine-learning-based approach to identifying suspicious network traffic from traffic-flow features.

The system uses the **CIC-IDS2017 dataset** to train and evaluate classification models, with XGBoost as the primary detection model and Random Forest as an alternative. A REST API exposes predictions, while PostgreSQL stores detection records for monitoring and analysis.

### Key Features

- **Machine Learning Detection:** Classifies network traffic using trained ML models.
- **Feature Selection:** Uses a fitted feature selector to retain relevant input features.
- **Model Optimization:** Supports hyperparameter tuning and model evaluation.
- **REST API:** Provides prediction and system-status endpoints using FastAPI.
- **Persistent Storage:** Stores detection results in PostgreSQL.
- **Monitoring Dashboard:** Displays detection summaries, traffic information, and threat-related metrics.
- **Traffic Simulation:** Supports testing the detection workflow with simulated traffic data.
- **Model Comparison:** Includes XGBoost and Random Forest model implementations.

## System Architecture

```mermaid
flowchart TD
    A[CIC-IDS2017 Dataset] --> B[Data Preprocessing]
    B --> C[Feature Selection]
    C --> D[Model Training and Evaluation]
    D --> E[XGBoost / Random Forest]
    E --> F[Serialized Model Artifacts]

    G[Network Traffic / Simulator] --> H[FastAPI]
    H --> I[Feature Validation and Selection]
    I --> J[Trained ML Model]
    J --> K[Intrusion Prediction]
    K --> L[PostgreSQL Database]
    K --> M[Monitoring Dashboard]
    L --> M
```

## Tech Stack

| Category | Technologies |
|---|---|
| Programming Language | Python |
| Machine Learning | XGBoost, Scikit-learn, Random Forest |
| Dataset | CIC-IDS2017 |
| API Framework | FastAPI |
| Database | PostgreSQL |
| Database Integration | SQLAlchemy |
| Traffic Analysis | Scapy |
| Model Persistence | Pickle (`.pkl`) |
| Containerization | Docker |
| Dashboard | Python-based web dashboard |

## Dataset

The project uses the **CIC-IDS2017 dataset**, a publicly available intrusion detection dataset containing benign network traffic and traffic associated with various attacks.

Dataset source: [CIC-IDS2017 — Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html)

The dataset supports model development and evaluation using network traffic features.

**Important:** Training data is not the same as live network traffic. Real-time detection requires a configured traffic capture or ingestion pipeline that extracts the same features expected by the trained model.

## Machine Learning Pipeline

1. **Data preprocessing:** Prepare traffic records and handle dataset formatting issues.
2. **Feature selection:** Apply the fitted feature selector to identify relevant features.
3. **Model training:** Train classification models, including XGBoost and Random Forest.
4. **Hyperparameter tuning:** Use search-based optimization to improve model configuration.
5. **Model evaluation:** Assess classification performance using suitable metrics.
6. **Model serialization:** Save trained models and preprocessing artifacts for inference.
7. **Prediction:** Load the artifacts into the API and classify incoming records.

### Evaluation Metrics

The models can be evaluated using:

- Precision
- Recall
- F1-score
- Confusion matrix
- ROC-AUC
- False-positive rate
- False-negative rate

For intrusion detection, recall and false-positive rate are particularly important: missed attacks can be costly, while excessive false alarms can overwhelm security analysts.

Actual performance depends on the evaluation split, class distribution, selected features, and whether the test data is independent of the training data.

## API

The FastAPI service exposes endpoints for predictions, model health, and dashboard data.

| Endpoint | Purpose |
|---|---|
| `GET /` | Application entry point |
| `GET /api/health` | Check API and model health |
| `GET /api/model` | Retrieve model information |
| `POST /api/predict` | Submit traffic features for classification |
| `GET /api/dashboard/summary` | Retrieve dashboard summary statistics |
| `GET /api/traffic` | Retrieve traffic-related data |
| `GET /api/threats` | Retrieve threat records |
| `GET /api/threat-score` | Retrieve threat-score information |
| `GET /api/status` | Retrieve application status |

Interactive API documentation is available at `/docs` when the FastAPI server is running and the documentation endpoint is enabled.

### Example Prediction Request

The precise request schema depends on the fields defined by the current API implementation.

```bash
curl -X POST "http://127.0.0.1:8000/api/predict" \
  -H "Content-Type: application/json" \
  -d '{
    "features": [0.1, 0.2, 0.3]
  }'
```

**Note:** The example above illustrates the request format only. Replace the sample values and payload structure with the exact feature schema accepted by your `/api/predict` endpoint. The model expects the correct feature count, ordering, and preprocessing.

## Project Structure

```text
AI-Based-Intrusion-Detection-System/
├── api/                  # FastAPI application and endpoints
├── data/                 # Dataset and data-processing resources
├── models/               # Trained models and preprocessing artifacts
├── dashboard/            # Monitoring dashboard
├── src/                  # ML pipeline and supporting modules
├── tests/                # Test suite
├── ai_ids_frontend/      # Legacy frontend, if retained
├── traffic_simulator.py   # Traffic simulation utility
├── README.md
└── requirements.txt      # Python dependencies, if present
```

The exact files and directories may vary with the current repository version.

## Getting Started

### Prerequisites

- Python 3.10 or a compatible version supported by the project dependencies
- PostgreSQL
- Git
- Docker and Docker Compose, if using the containerized setup

### 1. Clone the Repository

```bash
git clone https://github.com/upendraky/AI-Based-Intrusion-Detection-System.git
cd AI-Based-Intrusion-Detection-System
```

### 2. Create a Virtual Environment

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install Dependencies

If the repository contains a `requirements.txt` file:

```bash
pip install -r requirements.txt
```

Otherwise, install the dependencies specified by the project configuration.

### 4. Configure PostgreSQL

Create a PostgreSQL database and configure the connection string using the environment variable or configuration setting expected by the application.

Example connection string:

```text
postgresql://USERNAME:PASSWORD@localhost:5432/ids_database
```

Use your own credentials and database name. Do not commit passwords or production credentials to GitHub.

### 5. Verify Model Artifacts

The `models/` directory contains serialized model artifacts, including files such as:

- `best_ids_model.pkl`
- `feature_selector.pkl`
- `random_forest_ids.pkl`
- `xgboost_ids.pkl`
- `scaler.pkl`

Only the artifacts required by the current inference pipeline need to be present. Model files must be compatible with the installed Python and ML-library versions.

### 6. Start the API

Run the command that matches the FastAPI entry point in your repository. For example, if the application is defined in `api/main.py`:

```bash
uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

Open the API documentation at:

[http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### 7. Verify the Application

Check the health endpoint:

```bash
curl http://127.0.0.1:8000/api/health
```

Confirm that the API starts successfully, required model artifacts load, and the database connection is configured correctly.

**Dashboard startup:** Follow the entry-point instructions in the `dashboard/` directory. The dashboard command depends on how the current application is implemented.

## Security Considerations

- Treat model predictions as decision-support signals, not definitive proof of an attack.
- Keep database credentials and secret keys out of source control.
- Validate incoming feature data before inference.
- Restrict access to monitoring and administrative endpoints in production.
- Use authentication and HTTPS when exposing the API outside a trusted environment.
- Test the model against representative traffic and unseen attack patterns before operational deployment.

## Current Scope and Limitations

- Detection quality depends on the training dataset and feature distribution.
- Dataset-based evaluation does not, by itself, demonstrate production-grade live network detection.
- Traffic capture and feature extraction must match the trained model's expected schema.
- False positives and false negatives require ongoing evaluation.
- Production deployment requires appropriate access controls, logging, monitoring, and model-version management.

## Future Improvements

- Integrate a validated live packet-to-flow feature extraction pipeline.
- Add authentication and role-based dashboard access.
- Introduce alerting for high-risk detections.
- Add model drift monitoring and periodic evaluation.
- Expand testing across unseen attack categories and different traffic environments.
- Package the API and database using a production-ready Docker Compose configuration.

## Author

**Upendra Kumar Yadav**

B.Tech. — Computer Science and Engineering

GitHub: [@upendraky](https://github.com/upendraky)

## Disclaimer

This project is intended for educational, research, and authorized defensive cybersecurity use. Run traffic capture and security testing only on systems and networks for which you have permission.

