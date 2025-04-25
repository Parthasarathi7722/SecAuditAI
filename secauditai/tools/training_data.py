import json
import logging
import random
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import pandas as pd
from sklearn.model_selection import train_test_split
import torch
from transformers import AutoTokenizer, AutoModel
from tqdm import tqdm
import numpy as np

logger = logging.getLogger(__name__)

class TrainingData:
    """Tools for preparing and managing training data for AI models."""
    
    def __init__(self, data_dir: str = "training_data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.tokenizer = None
        self.model = None
    
    def prepare_dataset(self, input_path: str, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Prepare dataset for training.
        
        Args:
            input_path: Path to input dataset file
            output_dir: Optional output directory for prepared data
            
        Returns:
            Dict containing dataset statistics
        """
        output_dir = Path(output_dir) if output_dir else self.data_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Load and validate dataset
        dataset = self._load_dataset(input_path)
        valid_samples = self._validate_samples(dataset)
        
        # Split dataset
        train_data, val_data = train_test_split(
            valid_samples,
            test_size=0.2,
            random_state=42
        )
        
        # Save prepared datasets
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        train_path = output_dir / f"train_{timestamp}.json"
        val_path = output_dir / f"val_{timestamp}.json"
        
        self._save_dataset(train_data, train_path)
        self._save_dataset(val_data, val_path)
        
        return {
            "total_samples": len(dataset),
            "valid_samples": len(valid_samples),
            "train_samples": len(train_data),
            "val_samples": len(val_data),
            "train_path": str(train_path),
            "val_path": str(val_path)
        }
    
    def generate_embeddings(self, dataset_path: str, model_name: str = "microsoft/codebert-base") -> Dict[str, Any]:
        """
        Generate embeddings for code samples.
        
        Args:
            dataset_path: Path to dataset file
            model_name: Name of the model to use for embeddings
            
        Returns:
            Dict containing embedding statistics
        """
        if not self.tokenizer or not self.model:
            self._load_model(model_name)
        
        dataset = self._load_dataset(dataset_path)
        embeddings = []
        
        for sample in tqdm(dataset, desc="Generating embeddings"):
            try:
                code = sample["code"]
                inputs = self.tokenizer(
                    code,
                    return_tensors="pt",
                    truncation=True,
                    max_length=512,
                    padding="max_length"
                )
                
                with torch.no_grad():
                    outputs = self.model(**inputs)
                    embedding = outputs.last_hidden_state.mean(dim=1).squeeze().numpy()
                    embeddings.append(embedding)
            except Exception as e:
                logger.error(f"Failed to generate embedding: {e}")
        
        # Save embeddings
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = self.data_dir / f"embeddings_{timestamp}.npy"
        np.save(output_path, np.array(embeddings))
        
        return {
            "total_samples": len(dataset),
            "successful_embeddings": len(embeddings),
            "output_path": str(output_path)
        }
    
    def augment_dataset(self, dataset_path: str, output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Augment dataset with synthetic samples.
        
        Args:
            dataset_path: Path to input dataset
            output_path: Optional output path for augmented dataset
            
        Returns:
            Dict containing augmentation statistics
        """
        dataset = self._load_dataset(dataset_path)
        augmented_samples = []
        
        for sample in tqdm(dataset, desc="Augmenting dataset"):
            try:
                # Generate variations of the code
                variations = self._generate_variations(sample["code"])
                for var in variations:
                    augmented_sample = sample.copy()
                    augmented_sample["code"] = var
                    augmented_samples.append(augmented_sample)
            except Exception as e:
                logger.error(f"Failed to augment sample: {e}")
        
        # Save augmented dataset
        output_path = output_path or self.data_dir / f"augmented_{Path(dataset_path).name}"
        self._save_dataset(augmented_samples, output_path)
        
        return {
            "original_samples": len(dataset),
            "augmented_samples": len(augmented_samples),
            "output_path": str(output_path)
        }
    
    def _load_dataset(self, path: str) -> List[Dict[str, Any]]:
        """Load dataset from file."""
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load dataset: {e}")
            return []
    
    def _save_dataset(self, dataset: List[Dict[str, Any]], path: Path) -> None:
        """Save dataset to file."""
        try:
            with open(path, 'w') as f:
                json.dump(dataset, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save dataset: {e}")
    
    def _validate_samples(self, dataset: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate dataset samples."""
        valid_samples = []
        required_fields = ["code", "vulnerability_type", "language", "expected_findings"]
        
        for sample in dataset:
            if all(field in sample for field in required_fields):
                valid_samples.append(sample)
            else:
                logger.warning(f"Invalid sample: missing required fields")
        
        return valid_samples
    
    def _load_model(self, model_name: str) -> None:
        """Load model and tokenizer."""
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModel.from_pretrained(model_name)
            self.model.eval()
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            raise
    
    def _generate_variations(self, code: str) -> List[str]:
        """Generate variations of code samples."""
        variations = []
        
        # Add comments
        variations.append(f"# Original code\n{code}")
        
        # Change variable names
        var_map = {"x": "var1", "y": "var2", "z": "var3"}
        var_code = code
        for old, new in var_map.items():
            var_code = var_code.replace(old, new)
        variations.append(var_code)
        
        # Add whitespace
        variations.append(code.replace(" ", "  "))
        
        return variations 