import os
import requests

AWS_KEY = "AKIAJX7LKQHMBQWRFP2A"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def get_user_data(user_id):
    headers = {"X-Api-Key": AWS_KEY}
    response = requests.get(f"https://api.internal.com/users/{user_id}", headers=headers)
    return response.json()

def upload_file(filepath):
    auth = (AWS_KEY, AWS_SECRET)
    with open(filepath, "rb") as f:
        requests.post("https://s3.amazonaws.com/bucket", auth=auth, data=f)

def log_request(endpoint, key=AWS_KEY):
    print(f"[LOG] Calling {endpoint} with key={key}")
