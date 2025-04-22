#!/usr/bin/env python3
"""
Script to convert popular vulnerability detection datasets to SecAuditAI format.
"""

import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Any
import pandas as pd
import numpy as np
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def convert_codexglue(input_path: str, output_path: str) -> None:
    """Convert CodeXGLUE dataset to SecAuditAI format."""
    try:
        logger.info(f"Converting CodeXGLUE dataset from {input_path}")
        
        # Load CodeXGLUE dataset
        with open(input_path, 'r') as f:
            data = json.load(f)
        
        # Convert samples
        samples = []
        for item in data:
            sample = {
                'code': item['code'],
                'vulnerability_type': item['label'],
                'language': item.get('language', 'unknown'),
                'expected_findings': [
                    {
                        'type': item['label'],
                        'severity': 'high',
                        'description': f"Vulnerability of type {item['label']} detected",
                        'line': item.get('line', 0),
                        'column': item.get('column', 0)
                    }
                ]
            }
            samples.append(sample)
        
        # Save converted dataset
        output_data = {'samples': samples}
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        logger.info(f"Converted {len(samples)} samples to {output_path}")
        
    except Exception as e:
        logger.error(f"Error converting CodeXGLUE dataset: {e}")
        raise

def convert_bigvul(input_path: str, output_path: str) -> None:
    """Convert Big-Vul dataset to SecAuditAI format."""
    try:
        logger.info(f"Converting Big-Vul dataset from {input_path}")
        
        # Load Big-Vul dataset
        df = pd.read_csv(input_path)
        
        # Convert samples
        samples = []
        for _, row in df.iterrows():
            sample = {
                'code': row['code'],
                'vulnerability_type': row['vulnerability_type'],
                'language': 'c',
                'expected_findings': [
                    {
                        'type': row['vulnerability_type'],
                        'severity': 'high',
                        'description': f"Vulnerability of type {row['vulnerability_type']} detected",
                        'line': row.get('line', 0),
                        'column': row.get('column', 0)
                    }
                ]
            }
            samples.append(sample)
        
        # Save converted dataset
        output_data = {'samples': samples}
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        logger.info(f"Converted {len(samples)} samples to {output_path}")
        
    except Exception as e:
        logger.error(f"Error converting Big-Vul dataset: {e}")
        raise

def convert_devign(input_path: str, output_path: str) -> None:
    """Convert Devign dataset to SecAuditAI format."""
    try:
        logger.info(f"Converting Devign dataset from {input_path}")
        
        # Load Devign dataset
        with open(input_path, 'r') as f:
            data = json.load(f)
        
        # Convert samples
        samples = []
        for item in data:
            sample = {
                'code': item['func'],
                'vulnerability_type': 'vulnerable' if item['target'] == 1 else 'safe',
                'language': 'c',
                'expected_findings': [
                    {
                        'type': 'vulnerable' if item['target'] == 1 else 'safe',
                        'severity': 'high' if item['target'] == 1 else 'low',
                        'description': "Vulnerable code detected" if item['target'] == 1 else "Safe code",
                        'line': 0,
                        'column': 0
                    }
                ]
            }
            samples.append(sample)
        
        # Save converted dataset
        output_data = {'samples': samples}
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        logger.info(f"Converted {len(samples)} samples to {output_path}")
        
    except Exception as e:
        logger.error(f"Error converting Devign dataset: {e}")
        raise

def convert_sard(input_path: str, output_path: str) -> None:
    """Convert SARD dataset to SecAuditAI format."""
    try:
        logger.info(f"Converting SARD dataset from {input_path}")
        
        # Load SARD dataset
        with open(input_path, 'r') as f:
            data = json.load(f)
        
        # Convert samples
        samples = []
        for item in data:
            sample = {
                'code': item['code'],
                'vulnerability_type': item['vulnerability_type'],
                'language': item.get('language', 'c'),
                'expected_findings': [
                    {
                        'type': item['vulnerability_type'],
                        'severity': item.get('severity', 'high'),
                        'description': f"Vulnerability of type {item['vulnerability_type']} detected",
                        'line': item.get('line', 0),
                        'column': item.get('column', 0)
                    }
                ]
            }
            samples.append(sample)
        
        # Save converted dataset
        output_data = {'samples': samples}
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        logger.info(f"Converted {len(samples)} samples to {output_path}")
        
    except Exception as e:
        logger.error(f"Error converting SARD dataset: {e}")
        raise

def main():
    parser = argparse.ArgumentParser(
        description="Convert vulnerability detection datasets to SecAuditAI format"
    )
    parser.add_argument(
        "--dataset",
        required=True,
        choices=['codexglue', 'bigvul', 'devign', 'sard'],
        help="Dataset to convert"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to input dataset file"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to output JSON file"
    )
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Convert dataset based on type
    if args.dataset == 'codexglue':
        convert_codexglue(args.input, args.output)
    elif args.dataset == 'bigvul':
        convert_bigvul(args.input, args.output)
    elif args.dataset == 'devign':
        convert_devign(args.input, args.output)
    elif args.dataset == 'sard':
        convert_sard(args.input, args.output)

if __name__ == "__main__":
    main() 