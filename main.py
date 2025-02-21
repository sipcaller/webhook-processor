#!/usr/bin/env python3

import json
import logging
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime
from pathlib import Path
from importlib import import_module
import hmac
import hashlib
from logging.handlers import TimedRotatingFileHandler

# Default configuration and paths
CONFIG_FILE = Path("config.json")
LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "webhook_processor"
ACTIONS_DIR = Path("actions")

# Ensure logs directory exists
LOG_DIR.mkdir(exist_ok=True)

# Set up logging with daily rotation
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create a rotating file handler that changes daily and keeps 45 days
log_handler = TimedRotatingFileHandler(
    LOG_FILE,
    when='midnight',  # Rotate at midnight
    interval=1,       # Every 1 interval (day)
    backupCount=45,   # Keep logs for 45 days
    utc=False         # Use local time
)
log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
log_handler.suffix = "%Y-%m-%d.log"  # Append date to rotated files
log_handler.extMatch = r"^\d{4}-\d{2}-\d{2}\.log$"  # Match date format for rotation
logger.addHandler(log_handler)

class WebhookHandler(BaseHTTPRequestHandler):
    """Handle incoming webhook POST requests"""

    config = None

    def do_POST(self):
        """Process POST requests containing webhook data"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                logger.error("No data received in POST request")
                self.send_error(400, "No data received")
                return

            # Read the raw POST data first
            raw_data = self.rfile.read(content_length)
            webhook_data = json.loads(raw_data.decode('utf-8'))

            # Handle signature validation only if enabled
            validation_config = self.config.get('webhook_signature_validation', {})
            is_validation_enabled = validation_config.get('is_enabled', True)
            
            if is_validation_enabled:
                signature_header = self.headers.get('Sip-Caller-Signature')
                if not signature_header:
                    logger.error("Missing Sip-Caller-Signature header")
                    self.send_error(401, "Missing signature header")
                    return
                if not self.validate_signature(signature_header, raw_data):
                    logger.error("Invalid webhook signature")
                    self.send_error(401, "Invalid webhook signature")
                    return
            else:
                logger.warning("Signature validation disabled")

            # Log the received webhook
            log_entry = f"Received webhook: {json.dumps(webhook_data)}"
            logger.info(log_entry)

            # Process configured actions
            self.process_actions(webhook_data)

            # Send success response
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            response = {'status': 'success', 'message': 'Webhook processed'}
            self.wfile.write(json.dumps(response).encode('utf-8'))

        except json.JSONDecodeError:
            logger.error("Invalid JSON data in webhook payload")
            self.send_error(400, "Invalid JSON data")
        except ValueError as e:
            logger.error(f"Invalid content length: {str(e)}")
            self.send_error(400, "Invalid content length")
        except Exception as e:
            logger.error(f"Error processing webhook: {str(e)}")
            self.send_error(500, "Internal server error")

    def validate_signature(self, signature_header, raw_data):
        """Validate the webhook signature"""
        try:
            # Get signing secret from config
            signing_secret = self.config.get('webhook_signature_validation', {}).get('signing_secret', '').encode('utf-8')
            
            # Parse the signature header
            parts = dict(part.split('=') for part in signature_header.split(','))
            timestamp = parts.get('t')
            signature = parts.get('v1')
            
            if not timestamp or not signature:
                logger.error("Invalid signature header format")
                return False

            # Construct the signed payload
            signed_payload = f"{timestamp}.{raw_data.decode('utf-8')}".encode('utf-8')

            # Calculate expected signature
            expected_signature = hmac.new(
                signing_secret,
                signed_payload,
                hashlib.sha256
            ).hexdigest()

            # Compare signatures securely
            return hmac.compare_digest(expected_signature, signature)
        except Exception as e:
            logger.error(f"Signature validation error: {str(e)}")
            return False

    def process_actions(self, webhook_data):
        """Execute configured actions for the webhook"""
        actions = self.config.get('actions', {})
        for action_name, action_config in actions.items():
            try:
                # Import the action module dynamically
                action_module = import_module(f"actions.{action_name}")
                # Call the execute function from the action module
                action_module.execute(logger, webhook_data, action_config)
                logger.info(f"Action {action_name} executed successfully")
            except ImportError:
                logger.error(f"Action module {action_name} not found in actions directory")
            except AttributeError:
                logger.error(f"Action module {action_name} missing execute() function")
            except Exception as e:
                logger.error(f"Error executing action {action_name}: {str(e)}")

def load_config(config_path: Path) -> dict:
    """Load configuration from JSON file"""
    try:
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found at {config_path.absolute()}")
        
        if not config_path.is_file() or not config_path.stat().st_size > 0:
            raise ValueError(f"Configuration file at {config_path.absolute()} is not a valid file or is empty")
        
        logger.info(f"Attempting to load config from {config_path.absolute()}")
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        logger.debug(f"Raw config loaded: {json.dumps(config)}")
        
        # Validate required top-level parameters
        required_params = ['listen_address', 'listen_port', 'webhook_signature_validation']
        for param in required_params:
            if param not in config:
                raise ValueError(f"Missing required configuration parameter: {param}")
        
        # Validate port is an integer
        config['listen_port'] = int(config['listen_port'])
        if not (0 <= config['listen_port'] <= 65535):
            raise ValueError("listen_port must be between 0 and 65535")

        # Validate webhook_signature_validation section
        validation_config = config['webhook_signature_validation']
        required_validation_params = ['is_enabled', 'signing_secret']
        for param in required_validation_params:
            if param not in validation_config:
                raise ValueError(f"Missing required webhook_signature_validation parameter: {param}")
        
        if not isinstance(validation_config['is_enabled'], bool):
            raise ValueError("webhook_signature_validation.is_enabled must be a boolean")
        if not isinstance(validation_config['signing_secret'], str):
            raise ValueError("webhook_signature_validation.signing_secret must be a string")

        # Ensure actions directory exists
        ACTIONS_DIR.mkdir(exist_ok=True)
        
        logger.info("Configuration loaded and validated successfully")
        return config
    
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in configuration file {config_path.absolute()}: {str(e)}")
        raise
    except PermissionError as e:
        logger.error(f"Permission denied accessing configuration file {config_path.absolute()}: {str(e)}")
        raise
    except FileNotFoundError as e:
        logger.error(str(e))
        raise
    except Exception as e:
        logger.error(f"Failed to load configuration from {config_path.absolute()}: {str(e)}")
        raise

def run_server(config: dict):
    """Start the webhook server"""
    server_address = (config['listen_address'], config['listen_port'])
    
    WebhookHandler.config = config

    httpd = ThreadingHTTPServer(server_address, WebhookHandler)
    
    logger.info(f"Starting webhook processor on {config['listen_address']}:{config['listen_port']}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        httpd.server_close()
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        httpd.server_close()

def main():
    """Main entry point for the program"""
    # Check Python version
    if sys.version_info < (3, 8):
        print("Error: This program requires Python 3.8 or higher")
        sys.exit(1)

    # Load configuration
    try:
        config = load_config(CONFIG_FILE)
    except Exception as e:
        print(f"Error loading configuration: {str(e)}")
        sys.exit(1)

    # Run the server
    run_server(config)

if __name__ == '__main__':
    main()