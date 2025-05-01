# Troubleshooting Guide

This guide provides solutions for common issues encountered while using SecAuditAI.

## Installation Issues

### Python Environment Issues

1. **Virtual Environment Problems**
   ```bash
   # Create fresh virtual environment
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

2. **Dependency Conflicts**
   ```bash
   # Check for conflicts
   pip check
   
   # Resolve conflicts
   pip install --upgrade --force-reinstall -r requirements.txt
   ```

3. **Missing System Dependencies**
   ```bash
   # Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install build-essential python3-dev
   
   # CentOS/RHEL
   sudo yum groupinstall "Development Tools"
   sudo yum install python3-devel
   ```

### Docker Issues

1. **Permission Problems**
   ```bash
   # Add user to docker group
   sudo usermod -aG docker $USER
   
   # Restart Docker service
   sudo systemctl restart docker
   ```

2. **Container Startup Failures**
   ```bash
   # Check Docker logs
   docker-compose logs secauditai
   
   # Rebuild container
   docker-compose build --no-cache
   docker-compose up
   ```

3. **Volume Mount Issues**
   ```bash
   # Check volume permissions
   sudo chown -R $USER:$USER /path/to/volume
   
   # Verify mount points
   docker inspect secauditai | grep Mounts
   ```

## Tool-Specific Issues

### Cloud Scanning Issues

1. **AWS Authentication Problems**
   ```bash
   # Verify AWS credentials
   aws sts get-caller-identity
   
   # Check AWS CLI configuration
   aws configure list
   ```

2. **Azure Authentication Issues**
   ```bash
   # Login to Azure
   az login
   
   # Verify subscription
   az account show
   ```

3. **GCP Authentication Problems**
   ```bash
   # Authenticate with GCP
   gcloud auth login
   
   # Set project
   gcloud config set project PROJECT_ID
   ```

### Container Security Issues

1. **Image Scanning Failures**
   ```bash
   # Check Docker socket permissions
   sudo chmod 666 /var/run/docker.sock
   
   # Verify image exists
   docker images | grep IMAGE_NAME
   ```

2. **Runtime Monitoring Issues**
   ```bash
   # Check container status
   docker ps
   
   # Verify container logs
   docker logs CONTAINER_ID
   ```

### Zero-Day Detection Issues

1. **False Positives**
   ```bash
   # Adjust confidence threshold
   export SECAUDITAI_CONFIDENCE_THRESHOLD=0.9
   
   # Enable verbose logging
   export SECAUDITAI_DEBUG=true
   ```

2. **Performance Issues**
   ```bash
   # Limit scan scope
   secauditai scan --exclude tests/ --exclude vendor/
   
   # Adjust resource limits
   export SECAUDITAI_MEMORY_LIMIT=4G
   export SECAUDITAI_CPU_LIMIT=2
   ```

### Real-time Monitoring Issues

1. **High Resource Usage**
   ```bash
   # Adjust monitoring interval
   export SECAUDITAI_MONITOR_INTERVAL=300  # 5 minutes
   
   # Limit alert frequency
   export SECAUDITAI_MAX_ALERTS_PER_HOUR=5
   ```

2. **Notification Failures**
   ```bash
   # Test Slack integration
   secauditai test-notification slack
   
   # Test webhook
   secauditai test-notification webhook
   ```

## Performance Optimization

1. **Memory Usage**
   ```bash
   # Set memory limits
   export SECAUDITAI_MEMORY_LIMIT=4G
   
   # Enable garbage collection
   export SECAUDITAI_GC_THRESHOLD=0.8
   ```

2. **CPU Usage**
   ```bash
   # Limit CPU cores
   export SECAUDITAI_CPU_LIMIT=2
   
   # Adjust thread count
   export SECAUDITAI_THREADS=4
   ```

3. **Disk Usage**
   ```bash
   # Set cache directory
   export SECAUDITAI_CACHE_DIR=/tmp/cache
   
   # Limit cache size
   export SECAUDITAI_CACHE_SIZE=1G
   ```

## Integration Issues

1. **CI/CD Pipeline Failures**
   ```bash
   # Add proper exit codes
   secauditai scan --exit-code 1
   
   # Enable verbose logging
   secauditai scan --log-file scan.log
   ```

2. **Webhook Integration Problems**
   ```bash
   # Test webhook
   secauditai webhook test --url URL
   
   # Verify webhook secret
   secauditai webhook verify --secret SECRET
   ```

## Getting Help

1. **Check Logs**
   ```bash
   # View application logs
   tail -f /var/log/secauditai.log
   
   # Check Docker logs
   docker-compose logs -f
   ```

2. **Enable Debug Mode**
   ```bash
   export SECAUDITAI_DEBUG=true
   export SECAUDITAI_LOG_LEVEL=debug
   ```

3. **Submit Issue**
   ```bash
   # Generate debug information
   secauditai debug-info
   
   # Submit to GitHub
   secauditai submit-issue --debug-info debug.json
   ```

## Common Error Messages

1. **"Permission Denied"**
   - Solution: Check file permissions and Docker socket access
   ```bash
   sudo chown -R $USER:$USER /path/to/directory
   sudo chmod 666 /var/run/docker.sock
   ```

2. **"Connection Refused"**
   - Solution: Verify service is running and ports are open
   ```bash
   netstat -tulpn | grep LISTEN
   docker-compose ps
   ```

3. **"Resource Exhausted"**
   - Solution: Adjust resource limits
   ```bash
   export SECAUDITAI_MEMORY_LIMIT=8G
   export SECAUDITAI_CPU_LIMIT=4
   ```

For additional help, please:
1. Check the [GitHub Issues](https://github.com/Parthasarathi7722/SecAuditAI/issues)
2. Join our [Discord Community](https://discord.gg/secauditai)
3. Contact support at support@secauditai.com 