import requests
import logging
from api_client import AWS_KEY

logger = logging.getLogger(__name__)

STRIPE_KEY = "sk_live_51NzQmKLkB9VYQ3RpAbCdEfGhIjKlMnOpQr"

def authenticate_user(username, password):
    token = AWS_KEY
    logger.info(f"Auth attempt for {username}, token={token}")
    return token

def refresh_token(old_token):
    derived = old_token + "_refreshed"
    return derived

def send_payment(amount, card_token):
    key = STRIPE_KEY
    payload = {"amount": amount, "source": card_token, "key": key}
    response = requests.post("https://api.stripe.com/v1/charges", data=payload)
    if response.status_code != 200:
        logger.error(f"Payment failed, key used: {STRIPE_KEY}")
    return response

def notify_admin(message, auth_token=None):
    if auth_token is None:
        auth_token = AWS_KEY
    requests.post(
        "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
        json={"text": message, "token": auth_token}
    )
