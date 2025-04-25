# Use Python 3.13 as base image
FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    curl \
    wget \
    gnupg \
    lsb-release \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && apt-get install -y docker-ce-cli && rm -rf /var/lib/apt/lists/*

# Install kubectl
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install Grype (Anchore)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install Syft (Anchore)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Prowler
RUN pip install --no-cache-dir prowler-cloud

# Install OpenSCAP
RUN apt-get update && apt-get install -y openscap-scanner && rm -rf /var/lib/apt/lists/*

# Install InSpec
RUN curl -L https://omnitruck.chef.io/install.sh | bash -s -- -P inspec

# Copy requirements files
COPY requirements.txt .
COPY requirements-dev.txt .

# Install Python dependencies in stages
# 1. Core dependencies
RUN pip install --no-cache-dir \
    click>=8.0.0 \
    pyyaml>=6.0.0 \
    requests>=2.28.0 \
    python-dotenv>=1.0.0 \
    pydantic>=2.0.0 \
    tqdm>=4.65.0

# 2. Security scanning tools
RUN pip install --no-cache-dir \
    tree-sitter>=0.20.0

# 3. Cloud providers
RUN pip install --no-cache-dir \
    boto3>=1.26.0 \
    azure-mgmt-security>=3.0.0 \
    google-cloud-securitycenter>=1.20.0

# 4. Container security
RUN pip install --no-cache-dir \
    docker>=6.0.0 \
    kubernetes>=26.1.0

# 5. AI/ML
RUN pip install --no-cache-dir \
    torch>=2.0.0 \
    transformers>=4.30.0 \
    scikit-learn>=1.2.0 \
    pandas>=2.0.0 \
    numpy>=1.24.0

# 6. Monitoring and notifications
RUN pip install --no-cache-dir \
    watchdog>=3.0.0 \
    slack-sdk>=3.20.0

# 7. Testing
RUN pip install --no-cache-dir \
    pytest>=7.3.0 \
    pytest-cov>=4.0.0 \
    pytest-mock>=3.10.0

# 8. Development tools
RUN pip install --no-cache-dir \
    black>=23.3.0 \
    isort>=5.12.0 \
    flake8>=6.0.0 \
    mypy>=1.3.0 \
    pre-commit>=3.3.0

# 9. Documentation
RUN pip install --no-cache-dir \
    sphinx>=6.2.0 \
    sphinx-rtd-theme>=1.2.0 \
    mkdocs>=1.4.0 \
    mkdocs-material>=9.1.0

# 10. API and Web
RUN pip install --no-cache-dir \
    fastapi>=0.95.0 \
    uvicorn>=0.22.0 \
    jinja2>=3.1.0 \
    weasyprint>=59.0

# Copy the project files
COPY . .

# Install the package in development mode
RUN pip install -e .

# Set environment variables
ENV PYTHONPATH=/app
ENV PATH="/app:${PATH}"

# Create a non-root user
RUN useradd -m -u 1000 appuser
USER appuser

# Verify installations
RUN python -c "import click, yaml, requests, pydantic, tqdm, tree_sitter, boto3, docker, torch, transformers, sklearn, pandas, numpy, watchdog, slack_sdk, pytest, black, sphinx, fastapi, jinja2" && \
    grype --version && \
    syft --version && \
    prowler --version && \
    oscap --version && \
    inspec --version

# Default command
CMD ["python", "-m", "pytest", "tests/"] 