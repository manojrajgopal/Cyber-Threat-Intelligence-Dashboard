import os
import json
import logging
import time
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import numpy as np

# Directories
ARTIFACTS_DIR = 'training_artifacts'
LOGS_DIR = os.path.join(ARTIFACTS_DIR, 'logs')
METRICS_DIR = os.path.join(ARTIFACTS_DIR, 'metrics')
GRAPHS_DIR = os.path.join(ARTIFACTS_DIR, 'graphs')
INDIVIDUAL_GRAPHS_DIR = os.path.join(GRAPHS_DIR, 'individual')
SUMMARY_GRAPHS_DIR = os.path.join(GRAPHS_DIR, 'summary')
REPORTS_DIR = os.path.join(ARTIFACTS_DIR, 'reports')

for d in [LOGS_DIR, METRICS_DIR, INDIVIDUAL_GRAPHS_DIR, SUMMARY_GRAPHS_DIR, REPORTS_DIR]:
    os.makedirs(d, exist_ok=True)

def setup_logging(script_name):
    """Setup logging to console and file"""
    logger = logging.getLogger(script_name)
    logger.setLevel(logging.DEBUG)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)

    # File handler
    log_file = os.path.join(LOGS_DIR, f'{script_name}.log')
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger

class TrainingTimer:
    def __init__(self, logger):
        self.logger = logger
        self.start_time = None

    def start(self):
        self.start_time = time.time()
        self.logger.info("Training started")

    def elapsed(self):
        if self.start_time:
            return time.time() - self.start_time
        return 0

    def log_progress(self, message):
        elapsed = self.elapsed()
        self.logger.info(f"{message} - Elapsed time: {elapsed:.2f}s")

def calculate_classification_metrics(y_true, y_pred, logger):
    """Calculate and log classification metrics"""
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, average='weighted', zero_division=0)
    rec = recall_score(y_true, y_pred, average='weighted', zero_division=0)
    f1 = f1_score(y_true, y_pred, average='weighted', zero_division=0)
    cm = confusion_matrix(y_true, y_pred)

    metrics = {
        'accuracy': acc,
        'precision': prec,
        'recall': rec,
        'f1_score': f1,
        'confusion_matrix': cm.tolist()
    }

    logger.info(f"Accuracy: {acc:.4f}")
    logger.info(f"Precision: {prec:.4f}")
    logger.info(f"Recall: {rec:.4f}")
    logger.info(f"F1-Score: {f1:.4f}")
    logger.info(f"Confusion Matrix:\n{cm}")

    return metrics

def calculate_anomaly_metrics(scores, logger, threshold=0):
    """Calculate anomaly metrics"""
    anomalies = (scores < threshold).sum() if threshold == 0 else (scores > threshold).sum()  # For IF, negative scores are anomalies
    percentage = anomalies / len(scores) * 100

    metrics = {
        'anomaly_percentage': percentage,
        'anomaly_count': anomalies,
        'total_samples': len(scores)
    }

    logger.info(f"Anomaly Percentage: {percentage:.2f}%")
    logger.info(f"Anomaly Count: {anomalies}/{len(scores)}")

    return metrics

def save_metrics(metrics, script_name):
    """Save metrics to JSON"""
    # Convert numpy types to python types
    def convert(o):
        if isinstance(o, np.integer):
            return int(o)
        elif isinstance(o, np.floating):
            return float(o)
        elif isinstance(o, np.ndarray):
            return o.tolist()
        else:
            return o

    metrics_converted = {k: convert(v) for k, v in metrics.items()}
    metrics_file = os.path.join(METRICS_DIR, f'{script_name}_metrics.json')
    with open(metrics_file, 'w') as f:
        json.dump(metrics_converted, f, indent=4)

def plot_confusion_matrix(cm, script_name):
    """Plot and save confusion matrix"""
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title(f'Confusion Matrix - {script_name}')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.savefig(os.path.join(INDIVIDUAL_GRAPHS_DIR, f'{script_name}_confusion_matrix.png'))
    plt.close()

def plot_anomaly_scores(scores, script_name):
    """Plot anomaly scores histogram"""
    plt.figure(figsize=(8, 6))
    plt.hist(scores, bins=50, alpha=0.7)
    plt.title(f'Anomaly Scores Distribution - {script_name}')
    plt.xlabel('Anomaly Score')
    plt.ylabel('Frequency')
    plt.savefig(os.path.join(INDIVIDUAL_GRAPHS_DIR, f'{script_name}_anomaly_scores.png'))
    plt.close()

def plot_training_time(times, script_name):
    """Plot training time (dummy for now)"""
    plt.figure(figsize=(8, 6))
    plt.bar([script_name], [times])
    plt.title('Training Time')
    plt.ylabel('Time (s)')
    plt.savefig(os.path.join(INDIVIDUAL_GRAPHS_DIR, f'{script_name}_training_time.png'))
    plt.close()

def generate_report(script_name, algorithm, datasets, start_time, end_time, duration, metrics, model_path, graph_paths):
    """Generate training report"""
    report = {
        'model_name': script_name,
        'algorithm': algorithm,
        'datasets_used': datasets,
        'training_start_time': start_time,
        'training_end_time': end_time,
        'total_duration_seconds': duration,
        'metrics': metrics,
        'model_file_path': model_path,
        'graph_file_paths': graph_paths
    }

    # Convert numpy types
    def convert(o):
        if isinstance(o, np.integer):
            return int(o)
        elif isinstance(o, np.floating):
            return float(o)
        elif isinstance(o, np.ndarray):
            return o.tolist()
        else:
            return o

    def convert_dict(d):
        if isinstance(d, dict):
            return {k: convert_dict(v) for k, v in d.items()}
        elif isinstance(d, list):
            return [convert_dict(item) for item in d]
        else:
            return convert(d)

    report_converted = convert_dict(report)

    # JSON report
    json_file = os.path.join(REPORTS_DIR, f'{script_name}_report.json')
    with open(json_file, 'w') as f:
        json.dump(report_converted, f, indent=4)

    # Text report
    text_file = os.path.join(REPORTS_DIR, f'{script_name}_report.txt')
    with open(text_file, 'w') as f:
        f.write(f"Training Report for {script_name}\n")
        f.write(f"Algorithm: {algorithm}\n")
        f.write(f"Datasets: {', '.join(datasets)}\n")
        f.write(f"Start Time: {start_time}\n")
        f.write(f"End Time: {end_time}\n")
        f.write(f"Duration: {duration:.2f}s\n")
        f.write(f"Metrics: {json.dumps(report_converted['metrics'], indent=4)}\n")
        f.write(f"Model Path: {model_path}\n")
        f.write(f"Graphs: {', '.join(graph_paths)}\n")

    return json_file, text_file