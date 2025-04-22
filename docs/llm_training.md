# LLM Training for Vulnerability Detection

This guide explains how to train and fine-tune LLMs for vulnerability detection in SecAuditAI.

## Overview

SecAuditAI uses LLMs (Large Language Models) to detect security vulnerabilities in code and infrastructure configurations. The system supports multiple models and can be fine-tuned on custom datasets.

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

## Training Data

### Open Source Datasets

1. **CodeXGLUE**
   - Source: Microsoft
   - Contains code vulnerability examples
   - Multiple programming languages
   - [GitHub Repository](https://github.com/microsoft/CodeXGLUE)

2. **Big-Vul**
   - Source: National University of Singapore
   - Large-scale vulnerability dataset
   - C/C++ code examples
   - [Dataset Link](https://github.com/secureIT-project/Big-Vul)

3. **Devign**
   - Source: IBM
   - Vulnerability detection dataset
   - Multiple languages
   - [Paper](https://arxiv.org/abs/1909.03496)

4. **SARD**
   - Source: NIST
   - Software Assurance Reference Dataset
   - Known vulnerabilities
   - [Website](https://samate.nist.gov/SARD/)

### Custom Dataset Format

```json
{
  "samples": [
    {
      "code": "// Example vulnerable code\nchar buffer[10];\nstrcpy(buffer, user_input);",
      "vulnerability_type": "buffer_overflow",
      "language": "c",
      "expected_findings": [
        {
          "type": "buffer_overflow",
          "line": 3,
          "description": "Potential buffer overflow in strcpy",
          "severity": "high",
          "recommendation": "Use strncpy with proper size check"
        }
      ]
    }
  ]
}
```

## Training Process

1. **Data Preparation**
   ```bash
   # Convert dataset to required format
   python scripts/prepare_training_data.py --input dataset.json --output training_data.json
   ```

2. **Model Fine-tuning**
   ```python
   from secauditai.ai import AIManager
   
   ai = AIManager(config)
   result = ai.fine_tune_model(
       dataset_path="training_data.json",
       epochs=3,
       learning_rate=0.0001
   )
   ```

3. **Evaluation**
   ```python
   # Evaluate model performance
   metrics = ai.evaluate_model(test_data_path)
   print(f"Accuracy: {metrics['accuracy']}")
   print(f"Precision: {metrics['precision']}")
   print(f"Recall: {metrics['recall']}")
   ```

## Custom Vulnerability Patterns

You can add custom vulnerability patterns to enhance detection:

```python
pattern = {
    "id": "custom-001",
    "name": "Custom SQL Injection",
    "pattern": "raw\s*\([^)]*\+",
    "description": "Detects raw SQL query construction",
    "severity": "high",
    "confidence": 0.9
}

ai.add_custom_pattern(pattern)
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