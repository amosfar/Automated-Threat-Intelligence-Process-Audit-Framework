import json
import requests
import configparser
import time
import os

# Load config
config = configparser.ConfigParser()
config.read("config.ini")

VT_API_KEY = config["API"]["virustotal_key"]
INPUT_JSON = config["FILES"]["input_json"]
OUTPUT_JSON = config["FILES"]["output_json"]

VT_URL = "https://www.virustotal.com/api/v3/files/{}"
headers = {"x-apikey": VT_API_KEY}

# Cache to avoid duplicate VirusTotal requests
cache = {}


def vt_lookup(file_hash):
    """Send hash to VirusTotal and return malicious count, with caching."""

    # Skip no-hash or inaccessible
    if file_hash in ["NoHash", "AccessDenied", None]:
        return "NoHash"

    # Use cached result if available
    if file_hash in cache:
        return cache[file_hash]

    # Call VirusTotal API
    response = requests.get(VT_URL.format(file_hash), headers=headers)

    if response.status_code != 200:
        cache[file_hash] = "API_Error"
        return "API_Error"

    try:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", "Error")
    except Exception:
        malicious = "ParseError"

    # Store result in cache
    cache[file_hash] = malicious
    return malicious


def main():
    print("Loading process file:", INPUT_JSON)
    print("Absolute path Python is trying to open:", os.path.abspath(INPUT_JSON))

    # Load the JSON file
    with open(INPUT_JSON, "r") as f:
        processes = json.load(f)

    results = []

    for proc in processes:
        name = proc["Name"]
        h = proc["Hash"]

        print(f"Checking {name} ({h})...")

        malicious_count = vt_lookup(h)

        # Only sleep when doing new API requests
        if h not in ["NoHash", "AccessDenied", None] and h not in cache:
            time.sleep(1)

        results.append({
            "Process": name,
            "PID": proc["PID"],
            "MemoryMB": proc["MemoryMB"],
            "Hash": h,
            "MaliciousHits": malicious_count
        })

    # Save final JSON output
    with open(OUTPUT_JSON, "w") as outfile:
        json.dump(results, outfile, indent=4)

    # Summary
    print("\n=== Threat Report Summary ===")
    for entry in results:
        name = entry["Process"]
        hits = entry["MaliciousHits"]

        if isinstance(hits, int) and hits > 0:
            print(f"[MALICIOUS] {name} → {hits} detections")
        elif hits == 0:
            print(f"[CLEAN] {name}")
        else:
            print(f"[UNKNOWN] {name} → {hits}")

    print("\nSaved JSON report to:", OUTPUT_JSON)


if __name__ == "__main__":
    main()
