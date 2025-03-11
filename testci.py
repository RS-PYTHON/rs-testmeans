import requests
import time

for i in range(60):
    try:
        print(requests.get("http://prefect-server:4200/api/health"), flush=True)
    except Exception:
        print("KO", flush=True)
    time.sleep(1)