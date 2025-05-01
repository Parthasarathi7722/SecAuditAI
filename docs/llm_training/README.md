# LLM Training Guide

This guide provides detailed instructions for training and fine-tuning LLMs for security analysis in SecAuditAI.

## Overview

SecAuditAI uses LLMs for:
- Code vulnerability detection
- Security configuration analysis
- Zero-day vulnerability detection
- Security report generation

## Available Models

1. **Code Llama**
   - Specialized for code analysis
   - Best for detecting code-level vulnerabilities
   - Supports multiple programming languages

2. **Mistral**
   - General security analysis
   - Good for infrastructure and configuration analysis
   - Fast inference time

3. **Llama 2**
   - General-purpose analysis
   - Good for documentation and report generation
   - Versatile but less specialized

## Training Process

### 1. Data Preparation

```bash
# Create training dataset
python scripts/prepare_training_data.py \
    --input dataset.json \
    --output training_data.json \
    --format code \
    --language python

# Validate dataset
python scripts/validate_training_data.py \
    --dataset training_data.json \
    --rules validation_rules.json
```

### 2. Model Fine-tuning

```python
from secauditai.ai import AIManager

# Initialize AI manager
ai = AIManager(config)

# Fine-tune model
result = ai.fine_tune_model(
    dataset_path="training_data.json",
    model="code_llama",
    epochs=3,
    learning_rate=0.0001,
    batch_size=32
)

# Save model
ai.save_model("trained_model.pt")
```

### 3. Model Evaluation

```python
# Evaluate model
metrics = ai.evaluate_model(
    test_data_path="test_data.json",
    metrics=["accuracy", "precision", "recall", "f1"]
)

# Generate evaluation report
report = ai.generate_evaluation_report(
    metrics=metrics,
    format="html"
)
```

## Training Data Format

### Code Vulnerability Dataset

```json
{
  "samples": [
    {
      "code": "def unsafe_function():\n    pass",
      "vulnerability_type": "injection",
      "language": "python",
      "expected_findings": [
        {
          "type": "injection",
          "line": 2,
          "description": "Potential injection vulnerability",
          "severity": "high",
          "recommendation": "Use parameterized queries"
        }
      ]
    }
  ]
}
```

### Security Configuration Dataset

```json
{
  "samples": [
    {
      "config": {
        "aws": {
          "s3": {
            "bucket": "my-bucket",
            "public_access": true
          }
        }
      },
      "vulnerability_type": "misconfiguration",
      "expected_findings": [
        {
          "type": "public_access",
          "resource": "s3_bucket",
          "description": "S3 bucket has public access enabled",
          "severity": "high",
          "recommendation": "Disable public access"
        }
      ]
    }
  ]
}
```

## Custom Training

### 1. Create Custom Dataset

```python
from secauditai.ai import DatasetBuilder

# Initialize dataset builder
builder = DatasetBuilder()

# Add samples
builder.add_sample(
    code="vulnerable_code",
    vulnerability_type="injection",
    language="python"
)

# Save dataset
builder.save("custom_dataset.json")
```

### 2. Custom Model Architecture

```python
from secauditai.ai import ModelBuilder

# Initialize model builder
builder = ModelBuilder()

# Create custom model
model = builder.create_model(
    architecture="transformer",
    layers=12,
    heads=12,
    hidden_size=768
)

# Train model
model.train(
    dataset="custom_dataset.json",
    epochs=5,
    learning_rate=0.0001
)
```

### 3. Custom Training Pipeline

```python
from secauditai.ai import TrainingPipeline

# Initialize pipeline
pipeline = TrainingPipeline()

# Configure pipeline
pipeline.configure(
    model="custom_model",
    dataset="custom_dataset.json",
    optimizer="adamw",
    scheduler="cosine"
)

# Run training
pipeline.train(
    epochs=5,
    batch_size=32,
    validation_split=0.2
)
```

## Best Practices

1. **Data Quality**
   - Ensure balanced dataset
   - Include both vulnerable and secure code
   - Validate all examples

2. **Model Selection**
   - Choose model based on task
   - Consider inference time
   - Balance accuracy and performance

3. **Training Parameters**
   - Start with small learning rate
   - Use early stopping
   - Monitor loss and metrics

4. **Evaluation**
   - Use separate test set
   - Measure false positives/negatives
   - Compare with baseline

## Troubleshooting

1. **Poor Performance**
   - Check data quality
   - Adjust learning rate
   - Try different model

2. **Overfitting**
   - Reduce model complexity
   - Increase regularization
   - Add more training data

3. **Slow Training**
   - Use GPU acceleration
   - Reduce batch size
   - Optimize data pipeline

## Resources

- [Ollama Documentation](https://github.com/ollama/ollama)
- [Code Llama Paper](https://arxiv.org/abs/2308.12950)
- [Mistral Paper](https://arxiv.org/abs/2310.06825)
- [Llama 2 Paper](https://arxiv.org/abs/2307.09288) 