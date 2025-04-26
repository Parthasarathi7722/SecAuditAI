#!/usr/bin/env python3
"""
SecAuditAI Webhook Integration Example
This example demonstrates how to set up and handle webhooks from SecAuditAI.
"""

from flask import Flask, request, jsonify
from secauditai import Client
import hmac
import hashlib
import json

app = Flask(__name__)

# Initialize the client
client = Client(api_key="your-api-key")

# Your webhook secret (keep this secure!)
WEBHOOK_SECRET = "your-webhook-secret"

def verify_webhook_signature(payload, signature):
    """Verify the webhook signature."""
    expected_signature = hmac.new(
        WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected_signature)

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    # Get the signature from headers
    signature = request.headers.get('X-SecAuditAI-Signature')
    if not signature:
        return jsonify({"error": "Missing signature"}), 401
    
    # Get the raw payload
    payload = request.get_data()
    
    # Verify the signature
    if not verify_webhook_signature(payload, signature):
        return jsonify({"error": "Invalid signature"}), 401
    
    # Parse the payload
    data = json.loads(payload)
    
    # Handle different webhook events
    event_type = data.get('event')
    
    if event_type == 'scan.completed':
        # Handle scan completion
        scan_id = data.get('scan_id')
        results = data.get('results')
        print(f"Scan {scan_id} completed with results: {results}")
        
        # Example: Send notification to Slack
        # slack_notify(f"Scan {scan_id} completed: {results['summary']}")
        
    elif event_type == 'vulnerability.found':
        # Handle new vulnerability
        vuln = data.get('vulnerability')
        print(f"New vulnerability found: {vuln}")
        
        # Example: Create JIRA ticket
        # create_jira_ticket(vuln)
        
    elif event_type == 'compliance.violation':
        # Handle compliance violation
        violation = data.get('violation')
        print(f"Compliance violation detected: {violation}")
        
        # Example: Update compliance dashboard
        # update_compliance_dashboard(violation)
    
    return jsonify({"status": "success"})

def setup_webhook():
    """Set up the webhook in SecAuditAI."""
    webhook_url = "https://your-domain.com/webhook"
    events = ["scan.completed", "vulnerability.found", "compliance.violation"]
    
    response = client.webhook_create(
        url=webhook_url,
        events=events,
        secret=WEBHOOK_SECRET
    )
    print(f"Webhook created: {response}")

if __name__ == '__main__':
    # Set up the webhook (run this once)
    # setup_webhook()
    
    # Start the webhook server
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc') 