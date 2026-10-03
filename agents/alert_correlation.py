import json
import sys
from pathlib import Path


# ============================================================
# SENTINELFLOW AI
# Alert Correlation Agent
# ============================================================

# Find the project root directory
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
# ALERT CORRELATION FUNCTION
# ============================================================

def correlate_alert(alert_id):
    """
    Find security events related to a specific alert.

    The agent correlates information from:

    - SOC alerts
    - Authentication logs
    - Endpoint logs
    - Threat intelligence
    - Asset information
    """

    # Load all available security data
    alerts = load_json("alerts.json")
    auth_logs = load_json("auth_logs.json")
    endpoint_logs = load_json("endpoint_logs.json")
    threat_intel = load_json("threat_intel.json")
    assets = load_json("assets.json")

    # --------------------------------------------------------
    # Find the requested alert
    # --------------------------------------------------------

    alert = next(
        (item for item in alerts if item["alert_id"] == alert_id),
        None
    )

    # Alert not found
    if alert is None:
        return {
            "success": False,
            "error": f"Alert {alert_id} was not found."
        }

    # Extract important identifiers
    user = alert["user"]
    source_ip = alert["source_ip"]
    destination_asset = alert["destination_asset"]

    # --------------------------------------------------------
    # Find related authentication events
    # --------------------------------------------------------

    related_auth_events = [
        event
        for event in auth_logs
        if event["alert_id"] == alert_id
    ]

    # --------------------------------------------------------
    # Find related endpoint events
    # --------------------------------------------------------

    related_endpoint_events = [
        event
        for event in endpoint_logs
        if event["alert_id"] == alert_id
    ]

    # --------------------------------------------------------
    # Find threat intelligence information
    # --------------------------------------------------------

    related_threat_intel = [
        item
        for item in threat_intel
        if item["ip"] == source_ip
    ]

    # --------------------------------------------------------
    # Find asset information
    # --------------------------------------------------------

    related_asset = [
        item
        for item in assets
        if item["asset"] == destination_asset
    ]

    # --------------------------------------------------------
    # Build correlated evidence
    # --------------------------------------------------------

    result = {
        "success": True,
        "alert": alert,
        "user": user,
        "source_ip": source_ip,
        "destination_asset": destination_asset,
        "authentication_events": related_auth_events,
        "endpoint_events": related_endpoint_events,
        "threat_intelligence": related_threat_intel,
        "asset_context": related_asset
    }

    return result


# ============================================================
# DISPLAY CORRELATED RESULTS
# ============================================================

def display_result(result):
    """
    Display the correlated security information
    in a readable format.
    """

    if not result["success"]:

        print("\nERROR:")
        print(result["error"])
        return

    print("\n" + "=" * 60)
    print("SENTINELFLOW AI - ALERT CORRELATION AGENT")
    print("=" * 60)

    # --------------------------------------------------------
    # Alert information
    # --------------------------------------------------------

    print("\n[ALERT INFORMATION]")

    print("Alert ID:")
    print(f"  {result['alert']['alert_id']}")

    print("Alert Name:")
    print(f"  {result['alert']['alert_name']}")

    print("Case Type:")
    print(f"  {result['alert']['case_type']}")

    print("Description:")
    print(f"  {result['alert']['description']}")

    # --------------------------------------------------------
    # User information
    # --------------------------------------------------------

    print("\n[USER INFORMATION]")

    print("User:")
    print(f"  {result['user']}")

    # --------------------------------------------------------
    # Network information
    # --------------------------------------------------------

    print("\n[NETWORK INFORMATION]")

    print("Source IP:")
    print(f"  {result['source_ip']}")

    print("Destination Asset:")
    print(f"  {result['destination_asset']}")

    # --------------------------------------------------------
    # Authentication events
    # --------------------------------------------------------

    print("\n[AUTHENTICATION EVENTS]")

    if result["authentication_events"]:

        for event in result["authentication_events"]:

            print(
                f"  - {event['event']} "
                f"| {event['timestamp']}"
            )

    else:

        print("  No authentication events found.")

    # --------------------------------------------------------
    # Endpoint events
    # --------------------------------------------------------

    print("\n[ENDPOINT EVENTS]")

    if result["endpoint_events"]:

        for event in result["endpoint_events"]:

            print(
                f"  - Process: {event['process']} "
                f"| Suspicious: {event['suspicious']}"
            )

    else:

        print("  No endpoint events found.")

    # --------------------------------------------------------
    # Threat intelligence
    # --------------------------------------------------------

    print("\n[THREAT INTELLIGENCE]")

    if result["threat_intelligence"]:

        for item in result["threat_intelligence"]:

            print(
                f"  - Reputation: {item['reputation']} "
                f"| Confidence: {item['confidence']} "
                f"| Source: {item['source']}"
            )

    else:

        print("  No threat intelligence information found.")

    # --------------------------------------------------------
    # Asset context
    # --------------------------------------------------------

    print("\n[ASSET CONTEXT]")

    if result["asset_context"]:

        for asset in result["asset_context"]:

            print(
                f"  - Type: {asset['asset_type']} "
                f"| Criticality: {asset['criticality']} "
                f"| Owner: {asset['owner']} "
                f"| Environment: {asset['environment']}"
            )

    else:

        print("  No asset information found.")

    # --------------------------------------------------------
    # Correlation summary
    # --------------------------------------------------------

    print("\n[CORRELATION SUMMARY]")

    print(
        f"  Authentication events found: "
        f"{len(result['authentication_events'])}"
    )

    print(
        f"  Endpoint events found: "
        f"{len(result['endpoint_events'])}"
    )

    print(
        f"  Threat intelligence records: "
        f"{len(result['threat_intelligence'])}"
    )

    print(
        f"  Asset records found: "
        f"{len(result['asset_context'])}"
    )

    print("\n" + "=" * 60)
    print("CORRELATION COMPLETE")
    print("=" * 60)


# ============================================================
# MAIN PROGRAM
# ============================================================

if __name__ == "__main__":

    # --------------------------------------------------------
    # Allow alert ID to be supplied from the terminal
    #
    # Example:
    # python agents/alert_correlation.py INC-1003
    # --------------------------------------------------------

    if len(sys.argv) > 1:

        alert_id = sys.argv[1]

    else:

        # Default alert
        alert_id = "INC-1003"

    # Run correlation
    result = correlate_alert(alert_id)

    # Display results
    display_result(result)