# Contributing to SecAuditAI

Thank you for your interest in contributing to SecAuditAI! This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please be respectful and considerate of others.

## How to Contribute

### Reporting Issues

1. Check if the issue has already been reported in the [issue tracker](https://github.com/Parthasarathi7722/secauditai/issues)
2. If not, create a new issue with:
   - A clear, descriptive title
   - Detailed description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, etc.)

### Submitting Pull Requests

1. Fork the repository
2. Create a new branch for your feature/fix
3. Make your changes
4. Write/update tests
5. Update documentation
6. Run tests and linting
7. Submit a pull request

### Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Parthasarathi7722/secauditai.git
   cd secauditai
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

4. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

### Code Style

- Follow PEP 8 guidelines
- Use type hints
- Write docstrings for all public functions/classes
- Keep functions small and focused
- Use meaningful variable names

### Testing

- Write unit tests for new features
- Ensure all tests pass before submitting PR
- Maintain test coverage above 90%

### Documentation

- Update README.md for significant changes
- Add docstrings to new functions/classes
- Update API documentation if needed

### Commit Messages

- Use present tense
- Be descriptive but concise
- Reference issue numbers if applicable

## Project Structure

```
secauditai/
├── secauditai/          # Main package
│   ├── plugins/         # Scanner plugins
│   ├── ai/             # AI analysis components
│   ├── notifications/   # Notification handlers
│   └── ...
├── tests/              # Test files
├── docs/               # Documentation
└── examples/           # Usage examples
```

## Getting Help

- Check the [documentation](https://github.com/Parthasarathi7722/secauditai/docs)
- Join our [Discord community](https://discord.gg/secauditai)
- Open an issue for questions

## License

By contributing to SecAuditAI, you agree that your contributions will be licensed under the MIT License. 