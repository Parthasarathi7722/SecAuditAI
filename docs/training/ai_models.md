# AI Model Training Guide

This guide provides detailed instructions for training and fine-tuning the AI models used in SecAuditAI for code review and zero-day detection.

## Prerequisites

1. **Hardware Requirements**
   - GPU with at least 16GB VRAM
   - 32GB RAM
   - 500GB SSD storage
   - CUDA-compatible GPU

2. **Software Requirements**
   - Python 3.8+
   - PyTorch 1.8+
   - Transformers library
   - CUDA toolkit
   - Git

3. **Data Requirements**
   - Security dataset
   - Code repositories
   - Vulnerability database
   - Exploit samples

## Setup

1. **Environment Setup**
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install torch torchvision torchaudio
pip install transformers
pip install datasets
```

2. **Data Preparation**
```bash
# Clone security datasets
git clone https://github.com/security-datasets/code-vulnerabilities
git clone https://github.com/security-datasets/exploit-samples

# Prepare training data
python scripts/prepare_training_data.py \
    --vulnerabilities-dir code-vulnerabilities \
    --exploits-dir exploit-samples \
    --output-dir training_data
```

## Training CodeBERT

1. **Data Processing**
```python
from transformers import AutoTokenizer
from datasets import load_dataset

# Load and process dataset
def process_dataset():
    tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
    
    # Load security dataset
    dataset = load_dataset("security-dataset")
    
    # Tokenize code
    def tokenize_function(examples):
        return tokenizer(
            examples["code"],
            padding="max_length",
            truncation=True,
            max_length=512
        )
    
    # Process dataset
    tokenized_dataset = dataset.map(
        tokenize_function,
        batched=True,
        remove_columns=["code"]
    )
    
    return tokenized_dataset
```

2. **Model Training**
```python
from transformers import AutoModelForSequenceClassification, TrainingArguments, Trainer
import torch

def train_codebert():
    # Load processed dataset
    dataset = process_dataset()
    
    # Load model
    model = AutoModelForSequenceClassification.from_pretrained(
        "microsoft/codebert-base",
        num_labels=2
    )
    
    # Training arguments
    training_args = TrainingArguments(
        output_dir="./results",
        num_train_epochs=3,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        warmup_steps=500,
        weight_decay=0.01,
        logging_dir="./logs",
        logging_steps=10,
        evaluation_strategy="steps",
        eval_steps=500,
        save_strategy="steps",
        save_steps=500
    )
    
    # Initialize trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=dataset["train"],
        eval_dataset=dataset["validation"]
    )
    
    # Train model
    trainer.train()
    
    # Save model
    trainer.save_model("./models/codebert-security")
```

## Training LLM

1. **Data Processing**
```python
from transformers import GPT2Tokenizer
from datasets import load_dataset

def process_llm_dataset():
    tokenizer = GPT2Tokenizer.from_pretrained("gpt2")
    
    # Load security dataset
    dataset = load_dataset("security-llm-dataset")
    
    # Tokenize text
    def tokenize_function(examples):
        return tokenizer(
            examples["text"],
            padding="max_length",
            truncation=True,
            max_length=1024
        )
    
    # Process dataset
    tokenized_dataset = dataset.map(
        tokenize_function,
        batched=True,
        remove_columns=["text"]
    )
    
    return tokenized_dataset
```

2. **Model Training**
```python
from transformers import GPT2LMHeadModel, TrainingArguments, Trainer
import torch

def train_llm():
    # Load processed dataset
    dataset = process_llm_dataset()
    
    # Load model
    model = GPT2LMHeadModel.from_pretrained("gpt2")
    
    # Training arguments
    training_args = TrainingArguments(
        output_dir="./results",
        num_train_epochs=5,
        per_device_train_batch_size=4,
        per_device_eval_batch_size=4,
        warmup_steps=1000,
        weight_decay=0.01,
        logging_dir="./logs",
        logging_steps=10,
        evaluation_strategy="steps",
        eval_steps=500,
        save_strategy="steps",
        save_steps=500
    )
    
    # Initialize trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=dataset["train"],
        eval_dataset=dataset["validation"]
    )
    
    # Train model
    trainer.train()
    
    # Save model
    trainer.save_model("./models/llm-security")
```

## Model Evaluation

1. **Performance Metrics**
```python
from sklearn.metrics import precision_recall_fscore_support
import numpy as np

def evaluate_model(model, test_dataset):
    # Get predictions
    predictions = model.predict(test_dataset)
    
    # Calculate metrics
    precision, recall, f1, _ = precision_recall_fscore_support(
        test_dataset["labels"],
        predictions,
        average="weighted"
    )
    
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1
    }
```

2. **Zero-Day Detection Evaluation**
```python
def evaluate_zero_day_detection(model, test_dataset):
    # Get predictions
    predictions = model.predict(test_dataset)
    
    # Calculate detection rate
    true_positives = sum(1 for p, t in zip(predictions, test_dataset["labels"]) if p == 1 and t == 1)
    false_positives = sum(1 for p, t in zip(predictions, test_dataset["labels"]) if p == 1 and t == 0)
    false_negatives = sum(1 for p, t in zip(predictions, test_dataset["labels"]) if p == 0 and t == 1)
    
    precision = true_positives / (true_positives + false_positives)
    recall = true_positives / (true_positives + false_negatives)
    f1 = 2 * (precision * recall) / (precision + recall)
    
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives
    }
```

## Model Deployment

1. **Model Packaging**
```bash
# Package model
python scripts/package_model.py \
    --model-dir ./models/codebert-security \
    --output-dir ./deploy

# Create Docker image
docker build -t secauditai-ai-models .
```

2. **API Deployment**
```python
from fastapi import FastAPI
from transformers import pipeline

app = FastAPI()

# Load model
model = pipeline(
    "text-classification",
    model="./models/codebert-security"
)

@app.post("/analyze")
async def analyze_code(code: str):
    result = model(code)
    return {"result": result}
```

## Best Practices

1. **Data Quality**
   - Clean and preprocess data
   - Balance positive and negative samples
   - Validate data quality
   - Handle missing data

2. **Model Training**
   - Use appropriate batch size
   - Monitor training metrics
   - Implement early stopping
   - Save checkpoints

3. **Evaluation**
   - Use cross-validation
   - Test on unseen data
   - Monitor false positives/negatives
   - Regular performance assessment

4. **Deployment**
   - Version control models
   - Monitor model performance
   - Implement fallback mechanisms
   - Regular model updates

## Troubleshooting

1. **Common Issues**
   - Out of memory errors
   - Slow training
   - Poor model performance
   - Data quality issues

2. **Solutions**
   - Reduce batch size
   - Use gradient accumulation
   - Check data preprocessing
   - Adjust learning rate

## Maintenance

1. **Regular Updates**
   - Update training data
   - Retrain models
   - Evaluate performance
   - Update documentation

2. **Monitoring**
   - Track model performance
   - Monitor resource usage
   - Log errors and issues
   - Collect user feedback 