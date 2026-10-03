import sys

from agents.incident_investigation import investigate_incident


def generate_recommendations(result):
    """
    Generate response recommendations based on the
    investigation and risk assessment.

    IMPORTANT:
    This agent only recommends actions.
    It does NOT execute any real security action.
    """

    risk = result["risk"]
    investigation = result["investigation"]

    severity = risk.get("severity", "UNKNOWN")
    ambiguous = risk.get("ambiguous", False)

    recommendations = []
    priority = "LOW"
    approval_required = False
    automated_execution_allowed = False

    # ---------------------------------------------------------
    # AMBIGUOUS CASE
    # ---------------------------------------------------------

    if ambiguous:

        priority = "MEDIUM"
        approval_required = True

        recommendations.append(
            "Route incident to a SOC analyst for manual review."
        )

        recommendations.append(
            "Validate authentication activity with the affected user."
        )

        recommendations.append(
            "Review additional authentication and endpoint telemetry."
        )

        recommendations.append(
            "Do not perform account containment until evidence is validated."
        )

        recommendations.append(
            "Reassess the incident after additional evidence is collected."
        )

    # ---------------------------------------------------------
    # CRITICAL CASE
    # ---------------------------------------------------------

    elif severity == "CRITICAL":

        priority = "CRITICAL"
        approval_required = True

        recommendations.append(
            "Immediately escalate the incident to the senior SOC/security team."
        )

        recommendations.append(
            "Temporarily restrict or suspend the affected privileged account "
            "subject to human approval."
        )

        recommendations.append(
            "Investigate the affected critical production asset for "
            "unauthorised activity."
        )

        recommendations.append(
            "Review recent authentication, privilege and process activity "
            "associated with the account."
        )

        recommendations.append(
            "Consider isolating the affected endpoint or server "
            "subject to incident-response procedures."
        )

        recommendations.append(
            "Preserve relevant logs and forensic evidence for investigation."
        )

    # ---------------------------------------------------------
    # HIGH-RISK CASE
    # ---------------------------------------------------------

    elif severity == "HIGH":

        priority = "HIGH"
        approval_required = True

        recommendations.append(
            "Escalate the incident to a SOC/security analyst."
        )

        recommendations.append(
            "Review the affected account for signs of compromise."
        )

        recommendations.append(
            "Investigate authentication and endpoint activity "
            "associated with the alert."
        )

        recommendations.append(
            "Consider temporary account containment after human review."
        )

        recommendations.append(
            "Preserve relevant security telemetry for further investigation."
        )

    # ---------------------------------------------------------
    # MEDIUM-RISK CASE
    # ---------------------------------------------------------

    elif severity == "MEDIUM":

        priority = "MEDIUM"
        approval_required = True

        recommendations.append(
            "Route the incident to a SOC analyst for review."
        )

        recommendations.append(
            "Validate the unusual authentication activity."
        )

        recommendations.append(
            "Review threat intelligence and endpoint context."
        )

        recommendations.append(
            "Determine whether additional containment is necessary."
        )

    # ---------------------------------------------------------
    # LOW-RISK CASE
    # ---------------------------------------------------------

    else:

        priority = "LOW"
        approval_required = False

        recommendations.append(
            "Continue monitoring the affected account and asset."
        )

        recommendations.append(
            "Retain the alert and investigation evidence for audit purposes."
        )

        recommendations.append(
            "No immediate containment action is recommended."
        )

    return {
        "priority": priority,
        "recommendations": recommendations,
        "human_approval_required": approval_required,
        "automated_execution_allowed": automated_execution_allowed
    }


def generate_response_plan(alert_id):
    """
    Complete response recommendation workflow.
    """

    investigation_result = investigate_incident(alert_id)

    if not investigation_result["success"]:
        return {
            "success": False,
            "error": investigation_result["error"]
        }

    response = generate_recommendations(
        investigation_result
    )

    return {
        "success": True,
        "alert_id": alert_id,
        "risk": investigation_result["risk"],
        "investigation": investigation_result["investigation"],
        "response": response
    }


def display_result(result):
    """
    Display the recommended response plan.
    """

    if not result["success"]:
        print("\nERROR:")
        print(result["error"])
        return

    risk = result["risk"]
    response = result["response"]

    print("\n" + "=" * 75)
    print("SENTINELFLOW AI - RESPONSE RECOMMENDATION AGENT")
    print("=" * 75)

    print("\n[INCIDENT]")
    print(f"Alert ID: {result['alert_id']}")

    print("\n[RISK CONTEXT]")
    print(f"Risk Score: {risk['risk_score']}/100")
    print(f"Severity: {risk['severity']}")
    print(f"Confidence: {risk['confidence']}")
    print(f"Ambiguous: {risk['ambiguous']}")

    print("\n[RESPONSE PRIORITY]")
    print(f"Priority: {response['priority']}")

    print("\n[RECOMMENDED ACTIONS]")

    for index, recommendation in enumerate(
        response["recommendations"],
        start=1
    ):
        print(f"  {index}. {recommendation}")

    print("\n[GOVERNANCE CONTROL]")
    print(
        "Human Approval Required: "
        f"{response['human_approval_required']}"
    )

    print(
        "Automated High-Impact Execution Allowed: "
        f"{response['automated_execution_allowed']}"
    )

    print("\n[SAFETY PRINCIPLE]")
    print(
        "AI recommends response actions; "
        "humans retain control over consequential actions."
    )

    print("\n" + "=" * 75)
    print("RESPONSE RECOMMENDATION COMPLETE")
    print("=" * 75)


if __name__ == "__main__":

    if len(sys.argv) > 1:
        alert_id = sys.argv[1]
    else:
        alert_id = "INC-1003"

    result = generate_response_plan(alert_id)

    display_result(result)