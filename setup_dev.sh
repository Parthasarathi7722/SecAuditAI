#!/bin/bash

# Exit on error
set -e

echo "Setting up SecAuditAI development environment..."

# Create virtual environment
echo "Creating virtual environment..."
python -m venv venv

# Activate virtual environment
if [[ "$OSTYPE" == "linux-gnu"* || "$OSTYPE" == "darwin"* ]]; then
    source venv/bin/activate
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    source venv/Scripts/activate
else
    echo "Unsupported operating system"
    exit 1
fi

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Install development dependencies
echo "Installing development dependencies..."
pip install -e .

# Install Tree-sitter language parsers
echo "Installing Tree-sitter language parsers..."
python -c "import tree_sitter; tree_sitter.Language.build_library('build/my-languages.so', ['tree-sitter-python', 'tree-sitter-javascript', 'tree-sitter-java', 'tree-sitter-go'])"

# Create configuration directory
echo "Creating configuration directory..."
mkdir -p ~/.secauditai

# Initialize configuration
echo "Initializing configuration..."
secauditai init

echo "Development environment setup complete!"
echo "To activate the virtual environment:"
if [[ "$OSTYPE" == "linux-gnu"* || "$OSTYPE" == "darwin"* ]]; then
    echo "source venv/bin/activate"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    echo "source venv/Scripts/activate"
fi 