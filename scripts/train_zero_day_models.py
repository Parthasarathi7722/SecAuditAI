#!/usr/bin/env python3
"""
Script to train zero-day vulnerability detection models.
"""
import logging
import argparse
from pathlib import Path
from typing import Dict, Any, List
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import numpy as np
from datetime import datetime

from secauditai.ai.zero_day_detector import ZeroDayDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_training_data(input_path: str) -> Dict[str, Any]:
    """Load training data from JSON file."""
    try:
        with open(input_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading training data: {str(e)}")
        raise

def prepare_training_data(dataset: Dict[str, Any]) -> Dict[str, Any]:
    """Prepare training data for different models."""
    prepared_data = {
        'code_samples': [],
        'labels': [],
        'features': []
    }
    
    for sample in dataset['samples']:
        prepared_data['code_samples'].append(sample['code'])
        prepared_data['labels'].append(1 if sample['is_vulnerable'] else 0)
        prepared_data['features'].append(sample['features'])
    
    return prepared_data

def train_codebert_model(tokenizer, model, training_data: Dict[str, Any], output_dir: str):
    """Train CodeBERT model for semantic analysis."""
    logger.info("Training CodeBERT model...")
    
    # Prepare training data
    inputs = tokenizer(
        training_data['code_samples'],
        padding=True,
        truncation=True,
        max_length=512,
        return_tensors="pt"
    )
    labels = torch.tensor(training_data['labels'])
    
    # Training loop
    optimizer = torch.optim.AdamW(model.parameters(), lr=2e-5)
    criterion = torch.nn.CrossEntropyLoss()
    
    for epoch in range(3):
        model.train()
        optimizer.zero_grad()
        outputs = model(**inputs, labels=labels)
        loss = outputs.loss
        loss.backward()
        optimizer.step()
        
        logger.info(f"Epoch {epoch + 1}/3 - Loss: {loss.item():.4f}")
    
    # Save model
    model.save_pretrained(output_dir)
    tokenizer.save_pretrained(output_dir)
    logger.info(f"CodeBERT model saved to {output_dir}")

def train_anomaly_detector(training_data: Dict[str, Any], output_dir: str):
    """Train Isolation Forest model for anomaly detection."""
    logger.info("Training anomaly detection model...")
    
    # Prepare features
    scaler = StandardScaler()
    X = scaler.fit_transform(training_data['features'])
    
    # Train model
    model = IsolationForest(
        contamination=0.1,
        random_state=42
    )
    model.fit(X)
    
    # Save model and scaler
    joblib.dump(model, f"{output_dir}/anomaly_detector.joblib")
    joblib.dump(scaler, f"{output_dir}/scaler.joblib")
    logger.info(f"Anomaly detection model saved to {output_dir}")

def train_behavior_model(training_data: Dict[str, Any], output_dir: str):
    """Train behavior analysis model."""
    logger.info("Training behavior analysis model...")
    
    # Prepare data
    X = np.array(training_data['features'])
    y = np.array(training_data['labels'])
    
    # Create and train model
    model = torch.nn.Sequential(
        torch.nn.Linear(X.shape[1], 64),
        torch.nn.ReLU(),
        torch.nn.Linear(64, 32),
        torch.nn.ReLU(),
        torch.nn.Linear(32, 1),
        torch.nn.Sigmoid()
    )
    
    optimizer = torch.optim.Adam(model.parameters())
    criterion = torch.nn.BCELoss()
    
    X_tensor = torch.tensor(X, dtype=torch.float32)
    y_tensor = torch.tensor(y, dtype=torch.float32).unsqueeze(1)
    
    for epoch in range(10):
        optimizer.zero_grad()
        outputs = model(X_tensor)
        loss = criterion(outputs, y_tensor)
        loss.backward()
        optimizer.step()
        
        logger.info(f"Epoch {epoch + 1}/10 - Loss: {loss.item():.4f}")
    
    # Save model
    torch.save(model.state_dict(), f"{output_dir}/behavior_model.pt")
    logger.info(f"Behavior analysis model saved to {output_dir}")

def train_models(input_path: str, output_dir: str):
    """Train all zero-day detection models."""
    try:
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Load and prepare training data
        dataset = load_training_data(input_path)
        training_data = prepare_training_data(dataset)
        
        # Initialize models
        tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
        codebert_model = AutoModelForSequenceClassification.from_pretrained(
            "microsoft/codebert-base",
            num_labels=2
        )
        
        # Train models
        train_codebert_model(
            tokenizer,
            codebert_model,
            training_data,
            f"{output_dir}/codebert"
        )
        
        train_anomaly_detector(
            training_data,
            f"{output_dir}/anomaly"
        )
        
        train_behavior_model(
            training_data,
            f"{output_dir}/behavior"
        )
        
        logger.info("Training completed successfully")
        
    except Exception as e:
        logger.error(f"Error during training: {str(e)}")
        raise

def main():
    parser = argparse.ArgumentParser(description="Train zero-day vulnerability detection models")
    parser.add_argument(
        "--input",
        type=str,
        required=True,
        help="Path to training data JSON file"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="models/zero_day",
        help="Output directory for trained models"
    )
    
    args = parser.parse_args()
    
    # Add timestamp to output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"{args.output}_{timestamp}"
    
    train_models(args.input, output_dir)

if __name__ == "__main__":
    main() 