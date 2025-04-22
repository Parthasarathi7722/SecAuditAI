#!/usr/bin/env python3
"""
Script to generate training data for zero-day vulnerability detection.

This script generates synthetic training data for training AI models to detect security vulnerabilities.
It creates both vulnerable and secure code samples with various security patterns and features.

Features:
- Multiple vulnerability types (SQL injection, XSS, buffer overflow, etc.)
- Feature vectors for machine learning
- Metadata tracking
- Configurable sample generation
- Comprehensive logging

Usage:
    python generate_training_data.py [--vulnerable NUM] [--safe NUM] [--output PATH]

Example:
    python generate_training_data.py --vulnerable 2000 --safe 2000 --output data/training.json
"""
import logging
import argparse
import json
import random
from pathlib import Path
from typing import Dict, Any, List, Tuple
import numpy as np
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Feature vector indices
FEATURE_INDICES = {
    'sql_injection': 0,
    'xss': 1,
    'buffer_overflow': 2,
    'command_injection': 3,
    'path_traversal': 4,
    'insecure_deserialization': 5,
    'crypto_weakness': 6,
    'auth_bypass': 7,
    'severity': 8
}

def get_feature_vector(vulnerability_type: str, severity: float) -> List[float]:
    """Generate feature vector for a vulnerability type."""
    features = [0.0] * (len(FEATURE_INDICES) - 1)  # -1 for severity
    if vulnerability_type in FEATURE_INDICES:
        features[FEATURE_INDICES[vulnerability_type]] = 1.0
    features.append(severity)
    return features

def generate_vulnerable_code_samples(num_samples: int) -> List[Dict[str, Any]]:
    """Generate code samples with known vulnerabilities.
    
    Args:
        num_samples: Number of vulnerable samples to generate
        
    Returns:
        List of dictionaries containing vulnerable code samples
    """
    samples = []
    
    # Extended vulnerability patterns
    vulnerability_patterns = [
        # SQL Injection
        {
            'type': 'sql_injection',
            'code': 'query = f"SELECT * FROM users WHERE username = \'{user_input}\'"',
            'severity': 0.8
        },
        {
            'type': 'sql_injection',
            'code': 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            'severity': 0.9
        },
        
        # XSS
        {
            'type': 'xss',
            'code': 'document.write(user_input)',
            'severity': 0.7
        },
        {
            'type': 'xss',
            'code': 'element.innerHTML = user_input',
            'severity': 0.8
        },
        
        # Buffer Overflow
        {
            'type': 'buffer_overflow',
            'code': 'strcpy(buffer, user_input)',
            'severity': 0.9
        },
        {
            'type': 'buffer_overflow',
            'code': 'memcpy(dest, src, strlen(src))',
            'severity': 0.85
        },
        
        # Command Injection
        {
            'type': 'command_injection',
            'code': 'os.system(f"echo {user_input}")',
            'severity': 0.85
        },
        {
            'type': 'command_injection',
            'code': 'subprocess.call(f"ping {host}", shell=True)',
            'severity': 0.9
        },
        
        # Path Traversal
        {
            'type': 'path_traversal',
            'code': 'file = open(f"/var/www/{filename}", "r")',
            'severity': 0.8
        },
        {
            'type': 'path_traversal',
            'code': 'os.path.join(base_dir, user_input)',
            'severity': 0.75
        },
        
        # Insecure Deserialization
        {
            'type': 'insecure_deserialization',
            'code': 'pickle.loads(user_data)',
            'severity': 0.9
        },
        {
            'type': 'insecure_deserialization',
            'code': 'yaml.load(user_input)',
            'severity': 0.85
        },
        
        # Cryptographic Weaknesses
        {
            'type': 'crypto_weakness',
            'code': 'hash = hashlib.md5(password).hexdigest()',
            'severity': 0.7
        },
        {
            'type': 'crypto_weakness',
            'code': 'cipher = AES.new(key, AES.MODE_ECB)',
            'severity': 0.8
        },
        
        # Authentication Bypass
        {
            'type': 'auth_bypass',
            'code': 'if user_id == 1: admin = True',
            'severity': 0.9
        },
        {
            'type': 'auth_bypass',
            'code': 'if token == "admin": grant_access()',
            'severity': 0.85
        }
    ]
    
    for _ in range(num_samples):
        pattern = random.choice(vulnerability_patterns)
        features = get_feature_vector(pattern['type'], pattern['severity'])
        samples.append({
            'code': pattern['code'],
            'vulnerability_type': pattern['type'],
            'is_vulnerable': True,
            'features': features,
            'severity': pattern['severity']
        })
    
    return samples

def generate_safe_code_samples(num_samples: int) -> List[Dict[str, Any]]:
    """Generate safe code samples following security best practices.
    
    Args:
        num_samples: Number of safe samples to generate
        
    Returns:
        List of dictionaries containing safe code samples
    """
    samples = []
    
    # Safe code patterns
    safe_patterns = [
        # SQL Injection Prevention
        {
            'code': 'query = "SELECT * FROM users WHERE username = %s"',
            'type': 'sql_injection',
            'severity': 0.1
        },
        {
            'code': 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
            'type': 'sql_injection',
            'severity': 0.1
        },
        
        # XSS Prevention
        {
            'code': 'document.textContent = user_input',
            'type': 'xss',
            'severity': 0.1
        },
        {
            'code': 'element.setAttribute("data-content", user_input)',
            'type': 'xss',
            'severity': 0.1
        },
        
        # Buffer Overflow Prevention
        {
            'code': 'strncpy(buffer, user_input, sizeof(buffer))',
            'type': 'buffer_overflow',
            'severity': 0.1
        },
        {
            'code': 'memcpy_s(dest, sizeof(dest), src, strlen(src))',
            'type': 'buffer_overflow',
            'severity': 0.1
        },
        
        # Command Injection Prevention
        {
            'code': 'subprocess.run(["echo", user_input], capture_output=True)',
            'type': 'command_injection',
            'severity': 0.1
        },
        {
            'code': 'subprocess.run(["ping", host], capture_output=True)',
            'type': 'command_injection',
            'severity': 0.1
        },
        
        # Path Traversal Prevention
        {
            'code': 'file = open(os.path.join(base_dir, os.path.basename(filename)), "r")',
            'type': 'path_traversal',
            'severity': 0.1
        },
        {
            'code': 'safe_path = os.path.normpath(os.path.join(base_dir, filename))',
            'type': 'path_traversal',
            'severity': 0.1
        },
        
        # Secure Deserialization
        {
            'code': 'pickle.loads(user_data, fix_imports=False)',
            'type': 'insecure_deserialization',
            'severity': 0.1
        },
        {
            'code': 'yaml.safe_load(user_input)',
            'type': 'insecure_deserialization',
            'severity': 0.1
        },
        
        # Cryptographic Best Practices
        {
            'code': 'hash = hashlib.sha256(password).hexdigest()',
            'type': 'crypto_weakness',
            'severity': 0.1
        },
        {
            'code': 'cipher = AES.new(key, AES.MODE_GCM)',
            'type': 'crypto_weakness',
            'severity': 0.1
        },
        
        # Secure Authentication
        {
            'code': 'if user_id == admin_id and verify_token(token): admin = True',
            'type': 'auth_bypass',
            'severity': 0.1
        },
        {
            'code': 'if verify_jwt_token(token, secret): grant_access()',
            'type': 'auth_bypass',
            'severity': 0.1
        }
    ]
    
    for _ in range(num_samples):
        pattern = random.choice(safe_patterns)
        features = get_feature_vector(pattern['type'], pattern['severity'])
        samples.append({
            'code': pattern['code'],
            'vulnerability_type': 'none',
            'is_vulnerable': False,
            'features': features,
            'severity': pattern['severity']
        })
    
    return samples

def generate_training_data(
    num_vulnerable: int,
    num_safe: int,
    output_path: str
) -> None:
    """Generate training data and save to file.
    
    Args:
        num_vulnerable: Number of vulnerable samples to generate
        num_safe: Number of safe samples to generate
        output_path: Path to save the generated data
        
    Raises:
        Exception: If there's an error during data generation or saving
    """
    try:
        # Generate samples
        vulnerable_samples = generate_vulnerable_code_samples(num_vulnerable)
        safe_samples = generate_safe_code_samples(num_safe)
        
        # Combine and shuffle samples
        all_samples = vulnerable_samples + safe_samples
        random.shuffle(all_samples)
        
        # Create dataset
        dataset = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'num_samples': len(all_samples),
                'num_vulnerable': num_vulnerable,
                'num_safe': num_safe,
                'feature_vector_size': len(FEATURE_INDICES),
                'feature_indices': FEATURE_INDICES
            },
            'samples': all_samples
        }
        
        # Save to file
        with open(output_path, 'w') as f:
            json.dump(dataset, f, indent=2)
        
        logger.info(f"Generated {len(all_samples)} training samples")
        logger.info(f"Saved to {output_path}")
        
    except Exception as e:
        logger.error(f"Error generating training data: {str(e)}")
        raise

def main():
    parser = argparse.ArgumentParser(
        description="Generate training data for zero-day vulnerability detection",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--vulnerable",
        type=int,
        default=1000,
        help="Number of vulnerable code samples to generate"
    )
    parser.add_argument(
        "--safe",
        type=int,
        default=1000,
        help="Number of safe code samples to generate"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/training_data.json",
        help="Output path for training data"
    )
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    generate_training_data(args.vulnerable, args.safe, str(output_path))

if __name__ == "__main__":
    main() 