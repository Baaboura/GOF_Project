"""
High‑level Learning Agent orchestrator.

This module wraps the lower‑level services to provide an easy interface
for receiving alerts, training a model and predicting new alerts.
It deliberately omits any RAAD logic as requested; predictions are
solely based on the trained classifier.
"""

from typing import Dict, Optional

import numpy as np

from services.storage_service import StorageService
from services.preprocessing_service import PreprocessingService
from services.training_service import TrainingService
from services.prediction_service import PredictionService
from config import LABEL_COLUMN 


class LearningAgent:
    """Facilitate training and inference for the Learning Agent."""

    def __init__(self) -> None:
        self.storage = StorageService()
        self.preprocessing = PreprocessingService()
        self.training = TrainingService()
        self.predictor = PredictionService()

    def receive_alert(self, alert_json: Dict[str, any], human_feedback: Optional[str] = None) -> None:
        """Store a new alert along with optional human feedback."""
        self.storage.add_alert(alert_json, human_feedback)

    def train(self, version: str) -> Dict[str, float]:
        """Train a new model version using all labelled alerts.

        Parameters
        ----------
        version : str
            Identifier for the model version (e.g. 'v1').

        Returns
        -------
        Dict[str, float]
            Metrics on the test set: precision, recall, F1, false positive rate and threshold.
        """
        df = self.storage.get_labeled_data()
        if df.empty:
            raise ValueError("No labelled data to train on. Provide human feedback for alerts.")
        y = df[LABEL_COLUMN].astype(int).values
        X_df = df.drop(columns=[LABEL_COLUMN])
        X = self.preprocessing.fit_transform(X_df)
        model, metrics = self.training.train(
            X=X,
            y=y,
            preprocessor=self.preprocessing.preprocessor,
            feature_names=self.preprocessing.feature_names,
            version=version
        )
        return metrics

    def load_model(self, version: str) -> None:
        """Load an existing model for prediction."""
        self.predictor.load_model(version)

    def predict(self, alert_json: Dict[str, any]) -> Dict[str, float]:
        """Predict the class of a new alert using the loaded model."""
        return self.predictor.predict(alert_json)