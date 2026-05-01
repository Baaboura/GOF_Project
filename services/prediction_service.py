"""
Service for loading models and making predictions on new alerts.

This service loads a previously trained model and its preprocessing
pipeline, applies it to incoming alert data and returns a detailed
prediction report.
"""

import json
import os
from typing import Dict

import joblib
import numpy as np
import pandas as pd

from config import MODELS_DIR
from utils.json_utils import flatten_json
from services.report_service import ReportService


class PredictionService:
    """Load a model and predict the class of new alerts."""

    def __init__(self) -> None:
        self.model = None
        self.preprocessor = None
        self.feature_names = []
        self.threshold = 0.5

    def load_model(self, version: str) -> None:
        """Load a specific model version from disk."""
        model_path = os.path.join(MODELS_DIR, f"{version}.pkl")
        meta_path = os.path.join(MODELS_DIR, f"{version}.json")

        if not os.path.exists(model_path) or not os.path.exists(meta_path):
            raise FileNotFoundError(f"Model version {version} files not found.")

        data = joblib.load(model_path)
        self.model = data["model"]
        self.preprocessor = data["preprocessor"]
        self.feature_names = data["feature_names"]

        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        self.threshold = meta.get("threshold", 0.5)

    def predict(self, alert_json: Dict[str, any]) -> Dict[str, any]:
        """Predict a detailed result for a single alert."""

        if self.model is None or self.preprocessor is None:
            raise ValueError("Model not loaded. Call load_model() first.")

        # Flatten alert and align columns
        flat = flatten_json(alert_json)
        X = pd.DataFrame([flat])

        # Ensure all expected input columns are present
        for col in self.preprocessor.feature_names_in_:
            if col not in X.columns:
                X[col] = np.nan

        X = X[self.preprocessor.feature_names_in_]

        # Transform using the stored pipeline
        X_proc = self.preprocessor.transform(X)
        X_dense = X_proc.toarray() if hasattr(X_proc, "toarray") else X_proc

        prob = float(self.model.predict_proba(X_dense)[:, 1][0])
        decision = 1 if prob >= self.threshold else 0

        if prob >= 0.8:
            risk_level = "high"
            emoji = "🔴"
        elif prob >= 0.5:
            risk_level = "medium"
            emoji = "🟠"
        else:
            risk_level = "low"
            emoji = "🟢"

        decision_label = "threat" if decision == 1 else "benign"

        result = {
            "prediction_status": "success",
            "alert_summary": {
                "alert_type": alert_json.get("alert_type"),
                "source_agent": alert_json.get("source_agent"),
                "protocol": alert_json.get("protocol")
            },
            "model_output": {
                "probability": round(prob, 4),
                "threshold": float(self.threshold),
                "exceeds_threshold": bool(prob >= self.threshold),
                "decision": int(decision),
                "decision_label": decision_label
            },
            "risk_level": risk_level,
            "emoji_indicator": emoji,
            "explanation": (
                "The alert probability is higher than the selected threshold. "
                "The event is classified as a potential threat."
                if decision == 1
                else "The alert probability is below the threshold. "
                     "The event is classified as non-threatening."
            ),
            "recommendation": (
                "Trigger analyst review or response workflow."
                if decision == 1
                else "Store the alert for traceability and continue monitoring."
            )
        }

        reporter = ReportService()
        reporter.save_prediction_report(result)

        return result