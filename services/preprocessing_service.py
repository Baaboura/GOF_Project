"""
Service for preprocessing alert data before training.

This module builds and applies a Scikit‑learn ``ColumnTransformer``
pipeline to convert heterogeneous alert fields into a numerical feature
matrix.  Numeric columns are passed through unchanged, categorical
columns are one‑hot encoded, and the free‑text ``details`` column is
vectorised using TF–IDF.
"""

from typing import List, Optional

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder

from config import TEXT_COLUMN, MAX_TFIDF_FEATURES

class PreprocessingService:
    """Builds and applies preprocessing pipelines for alerts."""

    def __init__(self) -> None:
        self.preprocessor: Optional[ColumnTransformer] = None
        self.feature_names: List[str] = []

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        """Fit the preprocessing pipeline and transform the DataFrame.

        Parameters
        ----------
        df : pd.DataFrame
            DataFrame containing alert features (no label column).

        Returns
        -------
        np.ndarray
            The transformed feature matrix.
        """
        X = df.copy()
        numeric_cols = [c for c in X.columns if pd.api.types.is_numeric_dtype(X[c])]
        categorical_cols = [c for c in X.columns if pd.api.types.is_object_dtype(X[c]) and c != TEXT_COLUMN]
        text_cols = [TEXT_COLUMN] if TEXT_COLUMN in X.columns else []

        transformers = []
        if numeric_cols:
            transformers.append(('num', 'passthrough', numeric_cols))
        if categorical_cols:
            transformers.append(('cat', OneHotEncoder(handle_unknown='ignore'), categorical_cols))
        if text_cols:
            transformers.append(('txt', TfidfVectorizer(max_features=MAX_TFIDF_FEATURES, stop_words='english'), TEXT_COLUMN))

        self.preprocessor = ColumnTransformer(transformers)
        X_transformed = self.preprocessor.fit_transform(X)

        # Determine feature names for later use (e.g. saving models)
        self.feature_names = []
        if numeric_cols:
            self.feature_names += numeric_cols
        if categorical_cols:
            cat_names = self.preprocessor.named_transformers_['cat'].get_feature_names_out(categorical_cols)
            self.feature_names += list(cat_names)
        if text_cols:
            txt_names = self.preprocessor.named_transformers_['txt'].get_feature_names_out()
            self.feature_names += list(txt_names)

        return X_transformed

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """Transform new data using the fitted preprocessing pipeline."""
        if self.preprocessor is None:
            raise ValueError("Preprocessor has not been fitted. Call fit_transform first.")
        return self.preprocessor.transform(df)