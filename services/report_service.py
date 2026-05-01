import os
import json
from datetime import datetime
from config import OUTPUTS_DIR


class ReportService:
    def __init__(self):
        os.makedirs(OUTPUTS_DIR, exist_ok=True)

    def save_training_report(self, report, version):
        filename = f"{version}_training_result.json"
        path = os.path.join(OUTPUTS_DIR, filename)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)

    def save_prediction_report(self, report):
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S")
        filename = f"prediction_{timestamp}.json"
        path = os.path.join(OUTPUTS_DIR, filename)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)