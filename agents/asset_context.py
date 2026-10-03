import json
import sys
from pathlib import Path


# ============================================================
# SENTINELFLOW AI
# Asset Context Agent
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
# ASSET LOOKUP
# ============================================================

def investigate_asset(asset_name):
    """
    Retrieve business and security context
    for an asset.
    """

    assets = load_json("assets.json")

    # Find asset
    result = next(
        (
            item
            for item in assets
            if item["asset"] == asset_name
        ),
        None
    )

    # Asset not found
    if result is None:

        return {
            "success": True,
            "asset": asset_name,
            "found": False,
            "asset_type": "UNKNOWN",
            "criticality": "UNKNOWN",
            "owner": "UNKNOWN",
            "environment": "UNKNOWN"
        }

    return {
        "success": True,
        "asset": result["asset"],
        "found": True,
        "asset_type": result["asset_type"],
        "criticality": result["criticality"],
        "owner": result["owner"],
        "environment": result["environment"]
    }


# ============================================================
# DISPLAY RESULT
# ============================================================

def display_result(result):

    print("\n" + "=" * 60)
    print("SENTINELFLOW AI - ASSET CONTEXT AGENT")
    print("=" * 60)

    print("\n[ASSET]")
    print(f"Asset: {result['asset']}")

    print("\n[ASSET CONTEXT]")

    print(f"Asset Type: {result['asset_type']}")
    print(f"Criticality: {result['criticality']}")
    print(f"Owner: {result['owner']}")
    print(f"Environment: {result['environment']}")

    # Highlight critical assets
    if result["criticality"] == "CRITICAL":

        print("\n🔴 HIGH BUSINESS IMPACT")
        print("This asset is classified as CRITICAL.")

    elif result["criticality"] == "MEDIUM":

        print("\n🟡 MODERATE BUSINESS IMPACT")
        print("This asset has MEDIUM criticality.")

    elif result["criticality"] == "LOW":

        print("\n🟢 LOW BUSINESS IMPACT")
        print("This asset has LOW criticality.")

    else:

        print("\n? UNKNOWN CRITICALITY")
        print("Asset context is incomplete.")

    print("\n" + "=" * 60)
    print("ASSET CONTEXT CHECK COMPLETE")
    print("=" * 60)


# ============================================================
# MAIN PROGRAM
# ============================================================

if __name__ == "__main__":

    # Asset can be supplied through terminal.
    #
    # Example:
    # python agents/asset_context.py PROD-DB-01

    if len(sys.argv) > 1:

        asset_name = sys.argv[1]

    else:

        asset_name = "PROD-DB-01"

    result = investigate_asset(asset_name)

    display_result(result)