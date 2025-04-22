"""
Advanced AI models for zero-day vulnerability detection.
"""
import logging
from typing import Dict, Any, List
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from torch.utils.data import Dataset, DataLoader
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

class ZeroDayDetector:
    """Advanced AI models for zero-day vulnerability detection."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.models = self._load_models()
        self.tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
        
    def _load_models(self) -> Dict[str, Any]:
        """Load pre-trained models for zero-day detection."""
        models = {}
        
        # Load CodeBERT model for semantic analysis
        models['codebert'] = AutoModelForSequenceClassification.from_pretrained(
            "microsoft/codebert-base",
            num_labels=2
        )
        
        # Load anomaly detection model
        models['anomaly'] = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        
        # Load behavior analysis model
        models['behavior'] = torch.load('models/behavior_model.pt')
        
        return models
        
    def _analyze_code_semantics(self, code: str) -> Dict[str, float]:
        """Analyze code semantics using CodeBERT."""
        try:
            # Tokenize code
            inputs = self.tokenizer(
                code,
                return_tensors="pt",
                truncation=True,
                max_length=512
            )
            
            # Get model predictions
            with torch.no_grad():
                outputs = self.models['codebert'](**inputs)
                logits = outputs.logits
                probabilities = torch.softmax(logits, dim=1)
                
            return {
                'vulnerability_score': float(probabilities[0][1]),
                'confidence': float(torch.max(probabilities[0]))
            }
        except Exception as e:
            self.logger.error(f"Error in semantic analysis: {str(e)}")
            return {'vulnerability_score': 0.0, 'confidence': 0.0}
            
    def _detect_anomalies(self, features: List[float]) -> Dict[str, float]:
        """Detect anomalies in code patterns."""
        try:
            # Scale features
            scaler = StandardScaler()
            scaled_features = scaler.fit_transform([features])
            
            # Get anomaly score
            anomaly_score = self.models['anomaly'].score_samples(scaled_features)[0]
            
            return {
                'anomaly_score': float(anomaly_score),
                'is_anomaly': anomaly_score < -0.5
            }
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {str(e)}")
            return {'anomaly_score': 0.0, 'is_anomaly': False}
            
    def _analyze_behavior(self, code: str) -> Dict[str, float]:
        """Analyze code behavior patterns."""
        try:
            # Extract behavior features
            features = self._extract_behavior_features(code)
            
            # Get model predictions
            with torch.no_grad():
                outputs = self.models['behavior'](torch.tensor(features).float())
                behavior_score = float(outputs[0])
                
            return {
                'behavior_score': behavior_score,
                'suspicious': behavior_score > 0.7
            }
        except Exception as e:
            self.logger.error(f"Error in behavior analysis: {str(e)}")
            return {'behavior_score': 0.0, 'suspicious': False}
            
    def _extract_behavior_features(self, code: str) -> List[float]:
        """Extract behavior features from code."""
        features = []
        
        # Count suspicious patterns
        suspicious_patterns = [
            'eval(', 'exec(', 'system(', 'popen(',
            'shell=True', 'subprocess.call', 'os.system',
            'pickle.loads', 'yaml.load', 'json.loads'
        ]
        
        for pattern in suspicious_patterns:
            features.append(code.count(pattern))
            
        # Count dynamic code execution
        features.append(code.count('getattr'))
        features.append(code.count('setattr'))
        features.append(code.count('__import__'))
        
        # Count file operations
        features.append(code.count('open('))
        features.append(code.count('write('))
        
        # Count network operations
        features.append(code.count('socket.'))
        features.append(code.count('requests.'))
        
        return features
        
    def detect_zero_day(self, code: str) -> Dict[str, Any]:
        """Detect potential zero-day vulnerabilities."""
        try:
            # Run all detection methods
            semantic_results = self._analyze_code_semantics(code)
            behavior_features = self._extract_behavior_features(code)
            anomaly_results = self._detect_anomalies(behavior_features)
            behavior_results = self._analyze_behavior(code)
            
            # Combine results
            combined_score = (
                semantic_results['vulnerability_score'] * 0.4 +
                (1 - anomaly_results['anomaly_score']) * 0.3 +
                behavior_results['behavior_score'] * 0.3
            )
            
            # Determine if it's a potential zero-day
            is_zero_day = (
                combined_score > 0.7 or
                anomaly_results['is_anomaly'] or
                behavior_results['suspicious']
            )
            
            return {
                'is_zero_day': is_zero_day,
                'combined_score': float(combined_score),
                'semantic_analysis': semantic_results,
                'anomaly_detection': anomaly_results,
                'behavior_analysis': behavior_results,
                'confidence': min(
                    semantic_results['confidence'],
                    1 - anomaly_results['anomaly_score'],
                    behavior_results['behavior_score']
                )
            }
            
        except Exception as e:
            self.logger.error(f"Error in zero-day detection: {str(e)}")
            return {
                'is_zero_day': False,
                'combined_score': 0.0,
                'semantic_analysis': {'vulnerability_score': 0.0, 'confidence': 0.0},
                'anomaly_detection': {'anomaly_score': 0.0, 'is_anomaly': False},
                'behavior_analysis': {'behavior_score': 0.0, 'suspicious': False},
                'confidence': 0.0
            }
            
    def train_models(self, training_data: List[Dict[str, Any]]) -> None:
        """Train the zero-day detection models."""
        try:
            # Prepare training data
            X = []
            y = []
            
            for sample in training_data:
                features = self._extract_behavior_features(sample['code'])
                X.append(features)
                y.append(1 if sample['is_vulnerable'] else 0)
                
            # Train anomaly detection model
            self.models['anomaly'].fit(X)
            
            # Train behavior analysis model
            X_tensor = torch.tensor(X).float()
            y_tensor = torch.tensor(y).float()
            
            # Training loop
            optimizer = torch.optim.Adam(self.models['behavior'].parameters())
            criterion = torch.nn.BCELoss()
            
            for epoch in range(10):
                optimizer.zero_grad()
                outputs = self.models['behavior'](X_tensor)
                loss = criterion(outputs, y_tensor.unsqueeze(1))
                loss.backward()
                optimizer.step()
                
            # Save trained models
            torch.save(self.models['behavior'], 'models/behavior_model.pt')
            joblib.dump(self.models['anomaly'], 'models/anomaly_model.joblib')
            
        except Exception as e:
            self.logger.error(f"Error training models: {str(e)}") 