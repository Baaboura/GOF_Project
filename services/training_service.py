"""
Service for training and evaluating machine learning models.

This module trains a binary classifier on labelled alert data using
logistic regression. It splits the data into training and test sets,
calibrates a decision threshold based on F1 score and saves the
model together with its preprocessing pipeline and metadata.
"""

import json
import os
from typing import Dict, Tuple

from services.report_service import ReportService

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from config import MODELS_DIR, TEST_SIZE, RANDOM_STATE


class TrainingService:
    """Train and evaluate a logistic regression classifier."""

    def __init__(self) -> None:
        os.makedirs(MODELS_DIR, exist_ok=True)

    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        preprocessor: any,
        feature_names: list,
        version: str
    ) -> Tuple[any, Dict[str, float]]:
        """
        Train a model and return it together with evaluation metrics.
        """

        # Split into train/test sets
        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=TEST_SIZE,
            random_state=RANDOM_STATE,
            stratify=y
        )

        # Train logistic regression with class weighting to handle imbalance
        model = LogisticRegression(max_iter=1000, class_weight='balanced')
        model.fit(X_train, y_train)

        # Predict probabilities on test set
        y_prob = model.predict_proba(X_test)[:, 1]

        # Find best threshold by maximising F1
        thresholds = np.linspace(0, 1, 101)
        best_f1 = -1
        best_threshold = 0.5

        for t in thresholds:
            y_pred = (y_prob >= t).astype(int)
            current_f1 = f1_score(y_test, y_pred)

            if current_f1 > best_f1:
                best_f1 = current_f1
                best_threshold = float(t)

        # Final predictions at best threshold
        y_pred = (y_prob >= best_threshold).astype(int)

        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)

        # False positive rate
        fp = np.sum((y_test == 0) & (y_pred == 1))
        tn = np.sum((y_test == 0) & (y_pred == 0))
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        # Save model and preprocessing pipeline
        model_path = os.path.join(MODELS_DIR, f"{version}.pkl")
        meta_path = os.path.join(MODELS_DIR, f"{version}.json")

        joblib.dump(
            {
                "model": model,
                "preprocessor": preprocessor,
                "feature_names": feature_names
            },
            model_path
        )

        metadata = {
            "version": version,
            "threshold": float(best_threshold),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "fpr": float(fpr)
        }

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        validation_status = "accepted" if fpr <= 0.1 else "review_needed"

        validation_reason = (
            "False positive rate below 10%; model deemed acceptable."
            if fpr <= 0.1
            else "False positive rate exceeds 10%; review and tuning recommended."
        )

        recommendation = (
            "Consider adding more labelled alerts to improve robustness."
            if len(y) < 20
            else "Training data volume is sufficient for initial deployment."
        )

        training_report = {
            "model_version": version,
            "training_status": "success",
            "selected_threshold": float(best_threshold),
            "metrics": {
                "precision": float(precision),
                "recall": float(recall),
                "f1_score": float(f1),
                "false_positive_rate": float(fpr)
            },
            "model_validation": {
                "status": validation_status,
                "reason": validation_reason
            },
            "recommendation": recommendation,
            "emoji_summary": (
                "✅ Model accepted"
                if validation_status == "accepted"
                else "⚠️ Review needed"
            )
        }

        reporter = ReportService()
        reporter.save_training_report(training_report, version)

        return model, metadata