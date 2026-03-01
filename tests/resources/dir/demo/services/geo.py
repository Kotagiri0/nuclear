import requests
import json

GOOGLE_API_KEY = "AIzaSyD8mNpQrStUvWxYzAbCdEfGhIjKlMnOpQr"
MAPBOX_TOKEN = "pk.eyJ1IjoibXl1c2VyIiwiYSI6ImNrZXhhbXBsZXRva2VuMTIzNDU2Nzg5MCJ9.mNpQrStUvWxYzAbCdEf"

def geocode_address(address):
    url = f"https://maps.googleapis.com/maps/api/geocode/json"
    params = {"address": address, "key": GOOGLE_API_KEY}
    return requests.get(url, params=params).json()

def get_route(origin, dest):
    headers = {"Authorization": f"Bearer {MAPBOX_TOKEN}"}
    url = f"https://api.mapbox.com/directions/v5/mapbox/driving/{origin};{dest}"
    return requests.get(url, headers=headers).json()
