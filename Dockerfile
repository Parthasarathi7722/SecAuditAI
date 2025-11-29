# Multi-stage build for a clean, slim SecAuditAI Docker image
FROM python:3.13-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies system-wide
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Final stage - minimal runtime image
FROM python:3.13-slim

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install optional security tools
# Syft - SBOM generation (required for SBOM scanner)
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin && \
    rm -rf /tmp/*

# Note: Prowler is optional for cloud scanning
# To install Prowler, uncomment the following:
# RUN pip install --no-cache-dir prowler-cloud || \
#     (curl -sSfL https://raw.githubusercontent.com/prowler-cloud/prowler/main/install.sh | sh -s -- -b /usr/local/bin) || \
#     echo "Prowler installation skipped - cloud scanner will work with AWS SDK only"

# Set working directory
WORKDIR /app

# Copy application code
COPY secauditai/ ./secauditai/
COPY setup.py .
COPY pyproject.toml .
COPY requirements.txt .
COPY README.md .

# Copy Python packages from builder (system-wide installation)
# Ensure target directories exist and copy packages
RUN mkdir -p /usr/local/lib/python3.13/site-packages /usr/local/bin
COPY --from=builder /usr/local/lib/python3.13/site-packages/ /usr/local/lib/python3.13/site-packages/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

# Create a non-root user
RUN useradd -m -u 1000 appuser && \
    mkdir -p /home/appuser/.secauditai/results

# Install all dependencies from requirements.txt to ensure nothing is missing
# This ensures all packages (cryptography, PyJWT, SQLAlchemy, etc.) are available
RUN pip install --no-cache-dir -r requirements.txt

# Install the package system-wide (accessible to all users)
RUN pip install --no-cache-dir -e .

# Set ownership of user's home directory
RUN chown -R appuser:appuser /home/appuser

# Set environment variables
ENV PYTHONPATH=/app
ENV PATH="/usr/local/bin:${PATH}"

# Switch to non-root user
USER appuser

# Set working directory to user home
WORKDIR /home/appuser

# Default command
CMD ["python", "-m", "secauditai.cli", "--help"]
