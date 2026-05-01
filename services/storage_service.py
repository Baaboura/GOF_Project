"""
Service responsible for storing and retrieving alert data.

This module provides a simple interface for persisting alert events and
associated labels to a CSV file.  It uses the ``config`` module to
determine file paths and ensures directories are created as needed.
"""

import os
from typing import Dict, Optional

import pandas as pd

from config import ALERTS_FILE, DATA_DIR, LABEL_COLUMN
from utils.json_utils import flatten_json


class StorageService:
    """Persistent storage of alerts and their labels.

    The service loads the existing CSV file on initialisation and
    exposes methods to add new alerts or retrieve the data for
    processing.
    """

    def __init__(self) -> None:
        # Ensure the data directory exists
        os.makedirs(DATA_DIR, exist_ok=True)
        # Load existing data or create an empty DataFrame
        if os.path.exists(ALERTS_FILE):
            self.df = pd.read_csv(ALERTS_FILE)
        else:
            self.df = pd.DataFrame()

    def add_alert(self, alert_json: Dict[str, any], human_feedback: Optional[str] = None) -> None:
        """Add a new alert and optional label to storage.

        Parameters
        ----------
        alert_json : dict
            The alert data received from another agent.  Nested
            structures are flattened using dot notation.
        human_feedback : Optional[str], default ``None``
            Analyst feedback; valid values are ``'true_positive'`` or
            ``'false_positive'``.  If provided, it will be stored as a
            binary label (1 or 0) in the ``label`` column.
        """
        record = flatten_json(alert_json)
        if human_feedback is not None:
            if human_feedback not in ('true_positive', 'false_positive'):
                raise ValueError("human_feedback must be 'true_positive' or 'false_positive'")
            record[LABEL_COLUMN] = 1 if human_feedback == 'true_positive' else 0
        # Append to DataFrame
        self.df = pd.concat([self.df, pd.DataFrame([record])], ignore_index=True)
        # Persist to disk
        self.save()

    def save(self) -> None:
        """Persist the current DataFrame to the CSV file."""
        self.df.to_csv(ALERTS_FILE, index=False)

    def get_all_data(self) -> pd.DataFrame:
        """Return a copy of all stored alerts (including unlabelled)."""
        return self.df.copy()

    def get_labeled_data(self) -> pd.DataFrame:
        """Return only rows that have a defined label."""
        if LABEL_COLUMN not in self.df.columns:
            return pd.DataFrame()
        return self.df.dropna(subset=[LABEL_COLUMN]).copy()