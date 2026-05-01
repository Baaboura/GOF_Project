"""
Entry point for running the Learning Agent project.

This script demonstrates how to ingest alerts, train a model and make
predictions. It focuses on the supervised learning workflow.
Before running, ensure you have installed dependencies from
requirements.txt.
"""

import os
import json
from config import OUTPUTS_DIR
from agents.learning_agent import LearningAgent


def main() -> None:
    # Instantiate the agent
    agent = LearningAgent()

    # Example alerts with human feedback
    alert_1 = {
        'timestamp': '2026-04-05T10:00:00Z',
        'source_agent': 'analyzer_agent',
        'alert_type': 'malicious_code',
        'protocol': 'HTTP',
        'source_ip': '192.168.1.10',
        'destination_ip': '10.0.0.5',
        'details': 'possible virus detected in developer source code'
    }

    alert_2 = {
        'timestamp': '2026-04-05T10:30:00Z',
        'source_agent': 'detector_agent',
        'alert_type': 'unauthorized_access',
        'protocol': 'SSH',
        'source_ip': '192.168.1.12',
        'destination_ip': '10.0.0.9',
        'details': 'multiple suspicious login attempts detected'
    }

    # Store alerts with feedback
    agent.receive_alert(alert_1, human_feedback='false_positive')
    agent.receive_alert(alert_2, human_feedback='true_positive')

    # Train a model version if data is sufficient
    try:
        metrics = agent.train(version='v1')

        report_path = os.path.join(OUTPUTS_DIR, "v1_training_result.json")

        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as f:
                training_report = json.load(f)

            print("🎓 Training Summary:")
            print(f"  Version: {training_report['model_version']}")
            print(f"  Precision: {training_report['metrics']['precision']}")
            print(f"  Recall: {training_report['metrics']['recall']}")
            print(f"  F1-score: {training_report['metrics']['f1_score']}")
            print(f"  False positive rate: {training_report['metrics']['false_positive_rate']}")
            print(f"  Selected threshold: {training_report['selected_threshold']}")
            print(f"  Validation status: {training_report['model_validation']['status']} {training_report['emoji_summary']}")
            print(f"  Recommendation: {training_report['recommendation']}")
        else:
            print("Training finished. Metrics:", metrics)

    except Exception as e:
        print("Training error:", str(e))
        return

    # Load the model for inference
    agent.load_model('v1')

    # Predict a new alert
    new_alert = {
        'timestamp': '2026-04-05T11:00:00Z',
        'source_agent': 'analyzer_agent',
        'alert_type': 'malicious_code',
        'protocol': 'HTTP',
        'source_ip': '192.168.1.15',
        'destination_ip': '10.0.0.20',
        'details': 'developer uploaded modified internal source code'
    }

    prediction = agent.predict(new_alert)

    print("\n🔍 Prediction Summary:")
    print(f"  Probability: {prediction['model_output']['probability']} ({prediction['emoji_indicator']})")
    print(f"  Threshold: {prediction['model_output']['threshold']}")
    print(f"  Exceeds threshold: {prediction['model_output']['exceeds_threshold']}")
    print(f"  Decision: {prediction['model_output']['decision_label']} ({'🚨' if prediction['model_output']['decision'] == 1 else '✅'})")
    print(f"  Risk level: {prediction['risk_level']}")
    print(f"  Explanation: {prediction['explanation']}")
    print(f"  Recommendation: {prediction['recommendation']}")


if __name__ == '__main__':
    main()