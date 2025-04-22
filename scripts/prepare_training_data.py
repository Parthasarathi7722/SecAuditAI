#!/usr/bin/env python3
"""
Script to prepare training data for LLM vulnerability detection.
"""

import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Any
import random
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_dataset(input_path: str) -> Dict[str, Any]:
    """Load dataset from JSON file."""
    try:
        with open(input_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading dataset: {e}")
        raise

def validate_sample(sample: Dict[str, Any]) -> bool:
    """Validate a single sample from the dataset."""
    required_fields = ['code', 'vulnerability_type', 'language', 'expected_findings']
    return all(field in sample for field in required_fields)

def split_dataset(dataset: Dict[str, Any], train_ratio: float = 0.8) -> tuple:
    """Split dataset into training and validation sets."""
    samples = dataset['samples']
    random.shuffle(samples)
    
    split_idx = int(len(samples) * train_ratio)
    train_data = {'samples': samples[:split_idx]}
    val_data = {'samples': samples[split_idx:]}
    
    return train_data, val_data

def prepare_training_data(
    input_path: str,
    output_dir: str,
    train_ratio: float = 0.8
) -> None:
    """Prepare training data from input dataset."""
    try:
        # Create output directory
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Load and validate dataset
        logger.info(f"Loading dataset from {input_path}")
        dataset = load_dataset(input_path)
        
        # Validate samples
        valid_samples = [s for s in dataset['samples'] if validate_sample(s)]
        if len(valid_samples) != len(dataset['samples']):
            logger.warning(
                f"Filtered out {len(dataset['samples']) - len(valid_samples)} invalid samples"
            )
        dataset['samples'] = valid_samples
        
        # Split dataset
        logger.info("Splitting dataset into training and validation sets")
        train_data, val_data = split_dataset(dataset, train_ratio)
        
        # Save prepared datasets
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        train_path = output_path / f"train_{timestamp}.json"
        val_path = output_path / f"val_{timestamp}.json"
        
        with open(train_path, 'w') as f:
            json.dump(train_data, f, indent=2)
        logger.info(f"Saved training data to {train_path}")
        
        with open(val_path, 'w') as f:
            json.dump(val_data, f, indent=2)
        logger.info(f"Saved validation data to {val_path}")
        
        # Print statistics
        logger.info(f"Total samples: {len(dataset['samples'])}")
        logger.info(f"Training samples: {len(train_data['samples'])}")
        logger.info(f"Validation samples: {len(val_data['samples'])}")
        
    except Exception as e:
        logger.error(f"Error preparing training data: {e}")
        raise

def main():
    parser = argparse.ArgumentParser(
        description="Prepare training data for LLM vulnerability detection"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to input dataset JSON file"
    )
    parser.add_argument(
        "--output",
        default="training_data",
        help="Output directory for prepared datasets"
    )
    parser.add_argument(
        "--train-ratio",
        type=float,
        default=0.8,
        help="Ratio of data to use for training (default: 0.8)"
    )
    
    args = parser.parse_args()
    prepare_training_data(args.input, args.output, args.train_ratio)

if __name__ == "__main__":
    main() 