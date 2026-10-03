import json
import sys
from pathlib import Path


# ============================================================
# SENTINELFLOW AI
# Threat Intelligence Agent
# ============================================================

# Find project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Data directory
DATA_DIR = PROJECT_ROOT / "data"


# ============================================================
# LOAD JSON DATA
# ============================================================

def load_json(filename):
    """
    Load a JSON file from the data directory.
    """

    file_path = DATA_DIR / filename

    with open(file_path, "r") as file:
        return json.load(file)


# ============================================================
# THREAT INTELLIGENCE LOOKUP
# ============================================================

def investigate_ip(source_ip):
    """
    Investigate an IP address using the synthetic
    threat intelligence database.
    """

    threat_intel = load_json("threat_intel.json")

    # Find matching IP
    result = next(
        (
            item
            for item in threat_intel
            if item["ip"] == source_ip
        ),
        None
    )

    # IP not found
    if result is None:

        return {
            "success": True,
            "ip": source_ip,
            "reputation": "UNKNOWN",
            "confidence": 0.0,
            "source": "Synthetic Threat Intelligence Database",
            "found": False
        }

    # IP found
    return {
        "success": True,
        "ip": source_ip,
        "reputation": result["reputation"],
        "confidence": result["confidence"],
        "source": result["source"],
        "found": True
    }


# ============================================================
# DISPLAY RESULT
# ============================================================

def display_result(result):

    print("\n" + "=" * 60)
    print("SENTINELFLOW AI - THREAT INTELLIGENCE AGENT")
    print("=" * 60)

    print("\n[INDICATOR]")
    print(f"IP Address: {result['ip']}")

    print("\n[THREAT INTELLIGENCE RESULT]")
    print(f"Reputation: {result['reputation']}")
    print(f"Confidence: {result['confidence']}")
    print(f"Source: {result['source']}")

    if result["reputation"] == "MALICIOUS":

        print("\n⚠ WARNING")
        print("The source IP is classified as MALICIOUS.")

    elif result["reputation"] == "BENIGN":

        print("\n✓ SAFE")
        print("The source IP is classified as BENIGN.")

    else:

        print("\n? UNKNOWN")
        print("Insufficient threat intelligence evidence.")

    print("\n" + "=" * 60)
    print("THREAT INTELLIGENCE CHECK COMPLETE")
    print("=" * 60)


# ============================================================
# MAIN PROGRAM
# ============================================================

if __name__ == "__main__":

    # IP can be supplied through terminal
    #
    # Example:
    # python agents/threat_intelligence.py 185.22.14.91

    if len(sys.argv) > 1:

        source_ip = sys.argv[1]

    else:

        source_ip = "185.22.14.91"

    result = investigate_ip(source_ip)

    display_result(result)