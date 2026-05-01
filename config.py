"""
Central configuration for the Learning Agent project.

All constants such as paths, hyperparameters and default values are
defined here.  Modify this file to change the behaviour of the system.
"""

import os

# Determine base directory relative to this file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Data and model directories
DATA_DIR = os.path.join(BASE_DIR, 'data')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
OUTPUTS_DIR = os.path.join(BASE_DIR, "outputs")
# CSV file used to persist alerts and labels
ALERTS_FILE = os.path.join(DATA_DIR, 'alerts.csv')

# Names of important columns
TEXT_COLUMN = 'details'  # column containing free‑text descriptions
LABEL_COLUMN = 'label'   # column containing binary labels (1=true pos, 0=false pos)

# Preprocessing hyperparameters
MAX_TFIDF_FEATURES = 500  # maximum vocabulary size for TF–IDF

# Training hyperparameters
TEST_SIZE = 0.3  # proportion of data reserved for testing
RANDOM_STATE = 42  # seed for reproducibility

# Default decision threshold if calibration is not performed
DEFAULT_THRESHOLD = 0.5

__all__ = [
    'BASE_DIR',
    'DATA_DIR',
    'MODELS_DIR',
    'ALERTS_FILE',
    'TEXT_COLUMN',
    'LABEL_COLUMN',
    'MAX_TFIDF_FEATURES',
    'TEST_SIZE',
    'RANDOM_STATE',
    'DEFAULT_THRESHOLD',
    'OUTPUTS_DIR',
]