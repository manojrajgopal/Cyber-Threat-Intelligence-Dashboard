import json
import os
import matplotlib.pyplot as plt
from utils import SUMMARY_GRAPHS_DIR

def generate_summary_graph():
    """Generate summary graph from all metrics"""
    metrics_dir = 'training_artifacts/metrics'
    models = ['train_random_forest', 'train_logistic_regression', 'train_ensemble']
    accuracies = []
    times = []
    f1s = []

    for model in models:
        metrics_file = os.path.join(metrics_dir, f'{model}_metrics.json')
        if os.path.exists(metrics_file):
            with open(metrics_file, 'r') as f:
                data = json.load(f)
                accuracies.append(data.get('accuracy', 0))
                times.append(data.get('training_duration', 0))
                f1s.append(data.get('f1_score', 0))

    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(12, 10))

    # Accuracy
    ax1.bar(models, accuracies, color='blue')
    ax1.set_title('Model Accuracies')
    ax1.set_ylabel('Accuracy')

    # Training Time
    ax2.bar(models, times, color='green')
    ax2.set_title('Training Times')
    ax2.set_ylabel('Time (s)')

    # F1 Score
    ax3.bar(models, f1s, color='red')
    ax3.set_title('F1 Scores')
    ax3.set_ylabel('F1 Score')

    # Anomaly summary (placeholder)
    ax4.text(0.5, 0.5, 'Anomaly Detection\nSummary\n(Placeholder)', ha='center', va='center')
    ax4.set_title('Anomaly Summary')

    plt.tight_layout()
    plt.savefig(os.path.join(SUMMARY_GRAPHS_DIR, 'training_summary.png'))
    plt.close()

if __name__ == "__main__":
    generate_summary_graph()