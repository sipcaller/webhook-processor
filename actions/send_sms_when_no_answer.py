# actions/send_sms_when_no_answer.py
import requests
import logging

def execute(logger, webhook_data, action_config):
    """Execute the send_sms_when_no_answer action"""
    # Check if the call ring result is specifically "NoAnswer"
    ring_result = webhook_data.get('data', {}).get('callDetails', {}).get('ringResult', '')
    if ring_result == "NoAnswer":
        sms_url = action_config.get('url')
        sms_params = action_config.get('params', {}).copy()
        
        # Extract data from webhook to use in SMS
        phone_number = webhook_data.get('data', {}).get('callDetails', {}).get('number', '')
        var_values = webhook_data.get('data', {}).get('callDetails', {}).get('varValues', [])
        customer_name = var_values[0] if len(var_values) > 0 else ''
        
        # Simple template replacement
        message_template = sms_params.get('text', '')
        message = message_template.format(customer_name=customer_name)
        
        # Update params with actual values
        sms_params['to'] = phone_number
        sms_params['text'] = message

        # Send the SMS via POST request
        response = requests.post(sms_url, data=sms_params)
        response.raise_for_status()
        logger.info(f"SMS sent successfully to {phone_number} for unanswered call: {message}")
    else:
        logger.info(f"Call result was '{ring_result}', no SMS sent (requires 'NoAnswer')")
    