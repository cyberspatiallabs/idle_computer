import json
import os

import requests
from dotenv import load_dotenv

load_dotenv()

api_key = os.getenv("VIRUS_TOTAL_API_KEY")

# Load .har file
with open("data/accu.har", "r") as file:
    har_data = json.load(file)

# Extract URLs
urls = set()
for entry in har_data["log"]["entries"]:
    url = entry["request"]["url"]
    urls.add(url.split("/")[2])  # Get the domain

headers = {"x-apikey": api_key}

suspicious_urls = []
for url in urls:
    response = requests.get(
        f"https://www.virustotal.com/api/v3/domains/{url}", headers=headers
    )
    result = response.json()
    # Define your own criteria for suspicious
    if (
        result.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
        .get("malicious", 0)
        > 0
    ):
        suspicious_urls.append(url)

print("Suspicious URLs:", suspicious_urls)
