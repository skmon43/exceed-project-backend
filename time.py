from time import sleep
import requests

while True:
    response = requests.get("http://127.0.0.1:8000/hit_me")
    print(response)
    sleep(0.9)
