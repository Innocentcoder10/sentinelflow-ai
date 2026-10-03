import sys
from pathlib import Path

# ---------------------------------------------------------
# PROJECT PATH
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------
# IMPORT AGENTS
# ---------------------------------------------------------

from agents.alert_correlation import correlate_alert
from agents.threat_intelligence import investigate_ip
from agents.asset_context import investigate_asset
from agents.risk_agent import calculate_risk
from agents.incident_investigation import investigate_incident
from agents.response_recommendation import generate_response_plan


# ---------------------------------------------------------
# MAIN ORCHESTRATOR
# ---------------------------------------------------------

def process_alert(alert_id):
    """
    Execute the complete SentinelFlow AI workflow.

    The orchestrator coordinates all SOC agents and
    determines the appropriate routing decision.

    No high-impact security action is executed.
    """

    # -----------------------------------------------------
    # STEP 1 - ALERT CORRELATION
    # -----------------------------------------------------

    correlation = correlate_alert(alert_id)

    if not correlation["success"]:
        return {
            "success": False,
            "stage": "ALERT_CORRELATION",
            "error": correlation["error"]
        }

    alert = correlation["alert"]

    # -----------------------------------------------------
    # STEP 2 - THREAT INTELLIGENCE
    # -----------------------------------------------------

    source_ip = correlation["source_ip"]

    threat_intelligence = investigate_ip(
        source_ip
    )

    # -----------------------------------------------------
    # STEP 3 - ASSET CONTEXT
    # -----------------------------------------------------

    destination_asset = correlation["destination_asset"]

    asset_context = investigate_asset(
        destination_asset
    )

    # -----------------------------------------------------
    # STEP 4 - RISK ASSESSMENT
    # -----------------------------------------------------

    risk = calculate_risk(
        alert,
        threat_intelligence,
        asset_context
    )

    # -----------------------------------------------------
    # STEP 5 - INVESTIGATION
    # -----------------------------------------------------

    investigation = investigate_incident(
        alert_id
    )

    if not investigation["success"]:
        return {
            "success": False,
            "stage": "INCIDENT_INVESTIGATION",
            "error": investigation["error"]
        }

    # -----------------------------------------------------
    # STEP 6 - RESPONSE RECOMMENDATION
    # -----------------------------------------------------

    response = generate_response_plan(
        alert_id
    )

    if not response["success"]:
        return {
            "success": False,
            "stage": "RESPONSE_RECOMMENDATION",
            "error": response["error"]
        }

    # -----------------------------------------------------
    # STEP 7 - ROUTING DECISION
    # -----------------------------------------------------

    routing = determine_routing(
        risk
    )

    # -----------------------------------------------------
    # FINAL RESULT
    # -----------------------------------------------------

    return {
        "success": True,
        "alert_id": alert_id,

        "alert": alert,

        "correlation": correlation,

        "threat_intelligence": threat_intelligence,

        "asset_context": asset_context,

        "risk": risk,

        "investigation": investigation["investigation"],

        "response": response["response"],

        "routing": routing
    }


# ---------------------------------------------------------
# ROUTING LOGIC
# ---------------------------------------------------------

def determine_routing(risk):
    """
    Determine where the incident should go next.

    This is a governance-controlled routing layer.
    """

    severity = risk.get(
        "severity",
        "UNKNOWN"
    )

    ambiguous = risk.get(
        "ambiguous",
        False
    )

    # -----------------------------------------------------
    # AMBIGUOUS
    # -----------------------------------------------------

    if ambiguous:

        return {
            "route": "HUMAN_REVIEW",
            "priority": "MEDIUM",
            "reason": (
                "Evidence is incomplete or inconclusive. "
                "Human SOC analyst review is required."
            ),
            "human_required": True,
            "automated_action_allowed": False
        }

    # -----------------------------------------------------
    # CRITICAL
    # -----------------------------------------------------

    if severity == "CRITICAL":

        return {
            "route": "SECURITY_ESCALATION",
            "priority": "CRITICAL",
            "reason": (
                "Critical security indicators detected. "
                "Immediate escalation and human approval required."
            ),
            "human_required": True,
            "automated_action_allowed": False
        }

    # -----------------------------------------------------
    # HIGH
    # -----------------------------------------------------

    if severity == "HIGH":

        return {
            "route": "SOC_ESCALATION",
            "priority": "HIGH",
            "reason": (
                "High-risk activity detected. "
                "SOC review and approval required."
            ),
            "human_required": True,
            "automated_action_allowed": False
        }

    # -----------------------------------------------------
    # MEDIUM
    # -----------------------------------------------------

    if severity == "MEDIUM":

        return {
            "route": "SOC_ANALYST_REVIEW",
            "priority": "MEDIUM",
            "reason": (
                "Medium-risk activity detected. "
                "Analyst review is required."
            ),
            "human_required": True,
            "automated_action_allowed": False
        }

    # -----------------------------------------------------
    # LOW
    # -----------------------------------------------------

    return {
        "route": "MONITOR",
        "priority": "LOW",
        "reason": (
            "Low-risk activity detected. "
            "No immediate escalation is required."
        ),
        "human_required": False,
        "automated_action_allowed": False
    }


# ---------------------------------------------------------
# TERMINAL DISPLAY
# ---------------------------------------------------------

def display_result(result):

    if not result["success"]:

        print("\n" + "=" * 80)
        print("SENTINELFLOW AI - ORCHESTRATOR ERROR")
        print("=" * 80)

        print(f"\nFailed Stage: {result['stage']}")
        print(f"Error: {result['error']}")

        return

    risk = result["risk"]
    routing = result["routing"]
    investigation = result["investigation"]
    response = result["response"]

    print("\n" + "=" * 80)
    print("SENTINELFLOW AI - GOVERNED SOC ORCHESTRATOR")
    print("=" * 80)

    # -----------------------------------------------------
    # INCIDENT
    # -----------------------------------------------------

    print("\n[INCIDENT]")

    print(
        f"Alert ID: {result['alert_id']}"
    )

    print(
        f"Alert Name: {result['alert']['alert_name']}"
    )

    print(
        f"User: {result['alert']['user']}"
    )

    print(
        f"Source IP: {result['alert']['source_ip']}"
    )

    print(
        f"Destination Asset: "
        f"{result['alert']['destination_asset']}"
    )

    # -----------------------------------------------------
    # RISK
    # -----------------------------------------------------

    print("\n[RISK ASSESSMENT]")

    print(
        f"Risk Score: {risk['risk_score']}/100"
    )

    print(
        f"Severity: {risk['severity']}"
    )

    print(
        f"Confidence: {risk['confidence']}"
    )

    print(
        f"Ambiguous: {risk['ambiguous']}"
    )

    # -----------------------------------------------------
    # THREAT INTELLIGENCE
    # -----------------------------------------------------

    print("\n[THREAT INTELLIGENCE]")

    print(
        f"Reputation: "
        f"{result['threat_intelligence']['reputation']}"
    )

    print(
        f"Confidence: "
        f"{result['threat_intelligence']['confidence']}"
    )

    # -----------------------------------------------------
    # ASSET
    # -----------------------------------------------------

    print("\n[ASSET CONTEXT]")

    print(
        f"Criticality: "
        f"{result['asset_context']['criticality']}"
    )

    print(
        f"Environment: "
        f"{result['asset_context']['environment']}"
    )

    # -----------------------------------------------------
    # INVESTIGATION
    # -----------------------------------------------------

    print("\n[INVESTIGATION CONCLUSION]")

    print(
        investigation["conclusion"]
    )

    # -----------------------------------------------------
    # RESPONSE
    # -----------------------------------------------------

    print("\n[RESPONSE RECOMMENDATIONS]")

    for index, recommendation in enumerate(
        response["recommendations"],
        start=1
    ):

        print(
            f"  {index}. {recommendation}"
        )

    # -----------------------------------------------------
    # ROUTING
    # -----------------------------------------------------

    print("\n[ORCHESTRATOR ROUTING]")

    print(
        f"Route: {routing['route']}"
    )

    print(
        f"Priority: {routing['priority']}"
    )

    print(
        f"Reason: {routing['reason']}"
    )

    # -----------------------------------------------------
    # GOVERNANCE
    # -----------------------------------------------------

    print("\n[GOVERNANCE CONTROL]")

    print(
        "Human Required: "
        f"{routing['human_required']}"
    )

    print(
        "Automated High-Impact Action Allowed: "
        f"{routing['automated_action_allowed']}"
    )

    print(
        "\nAI Recommendation Only: "
        "Human retains control over consequential actions."
    )

    print("\n" + "=" * 80)
    print("SENTINELFLOW AI - END-TO-END PROCESS COMPLETE")
    print("=" * 80)


# ---------------------------------------------------------
# PROGRAM ENTRY POINT
# ---------------------------------------------------------

if __name__ == "__main__":

    if len(sys.argv) > 1:
        alert_id = sys.argv[1]

    else:
        alert_id = "INC-1003"

    result = process_alert(
        alert_id
    )

    display_result(
        result
    )