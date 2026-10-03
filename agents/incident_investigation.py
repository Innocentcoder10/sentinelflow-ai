import sys
from pathlib import Path

from agents.risk_agent import analyse_alert

def build_timeline(correlation):
    """
    Build a chronological incident timeline from authentication
    and endpoint evidence.
    """

    timeline = []

    # Authentication events
    for event in correlation.get("auth_events", []):
        timeline.append({
            "timestamp": event.get("timestamp", "UNKNOWN"),
            "event_type": event.get("event", "UNKNOWN"),
            "source": "Authentication Logs",
            "details": (
                f"User {event.get('user', 'UNKNOWN')} "
                f"from IP {event.get('source_ip', 'UNKNOWN')}"
            )
        })

    # Endpoint events
    for event in correlation.get("endpoint_events", []):
        timeline.append({
            "timestamp": "N/A",
            "event_type": "ENDPOINT_ACTIVITY",
            "source": "Endpoint Logs",
            "details": (
                f"Process {event.get('process', 'UNKNOWN')} "
                f"on asset {event.get('asset', 'UNKNOWN')}"
            )
        })

    # Sort events where timestamps exist
    timeline.sort(
        key=lambda x: x.get("timestamp", "")
    )

    return timeline


def identify_indicators(alert, threat_intelligence, asset_context):
    """
    Identify security indicators from available evidence.
    """

    indicators = []

    # Authentication indicators
    failed_logins = alert.get("failed_login_count", 0)

    if failed_logins >= 10:
        indicators.append(
            f"High volume of failed login attempts ({failed_logins})"
        )
    elif failed_logins > 0:
        indicators.append(
            f"Failed login activity detected ({failed_logins} attempts)"
        )

    if alert.get("successful_login", False):
        indicators.append(
            "Successful authentication occurred"
        )

    # Geographic indicators
    if alert.get("impossible_travel", False):
        indicators.append(
            "Impossible-travel condition detected"
        )

    # Account privilege
    if alert.get("privileged_account", False):
        indicators.append(
            "Privileged account involved"
        )

    # Endpoint indicators
    if alert.get("suspicious_process", False):
        indicators.append(
            "Suspicious endpoint process detected"
        )

    # Threat intelligence
    reputation = threat_intelligence.get(
        "reputation",
        "UNKNOWN"
    )

    if reputation == "MALICIOUS":
        indicators.append(
            "Source IP has MALICIOUS threat intelligence reputation"
        )
    elif reputation == "UNKNOWN":
        indicators.append(
            "Source IP reputation is UNKNOWN"
        )
    elif reputation == "BENIGN":
        indicators.append(
            "Source IP has BENIGN threat intelligence reputation"
        )

    # Asset criticality
    criticality = asset_context.get(
        "criticality",
        "UNKNOWN"
    )

    if criticality == "CRITICAL":
        indicators.append(
            "Target asset is classified as CRITICAL"
        )
    elif criticality == "MEDIUM":
        indicators.append(
            "Target asset has MEDIUM criticality"
        )
    elif criticality == "LOW":
        indicators.append(
            "Target asset has LOW criticality"
        )

    return indicators


def determine_investigation_conclusion(
    alert,
    threat_intelligence,
    asset_context,
    risk
):
    """
    Generate a deterministic investigation conclusion
    based on the available evidence.
    """

    reputation = threat_intelligence.get(
        "reputation",
        "UNKNOWN"
    )

    criticality = asset_context.get(
        "criticality",
        "UNKNOWN"
    )

    privileged = alert.get(
        "privileged_account",
        False
    )

    impossible_travel = alert.get(
        "impossible_travel",
        False
    )

    suspicious_process = alert.get(
        "suspicious_process",
        False
    )

    ambiguous = risk.get(
        "ambiguous",
        False
    )

    severity = risk.get(
        "severity",
        "UNKNOWN"
    )

    # High-confidence compromise indicators
    if (
        reputation == "MALICIOUS"
        and privileged
        and criticality == "CRITICAL"
        and suspicious_process
    ):
        return (
            "Strong indicators of potential privileged "
            "account compromise involving a critical asset."
        )

    # Ambiguous investigation
    if ambiguous:
        return (
            "Evidence indicates a potential security anomaly, "
            "but available evidence is insufficient for a "
            "high-confidence conclusion. Human SOC analyst "
            "review is required."
        )

    # Medium/high severity investigation
    if (
        impossible_travel
        and severity in ["MEDIUM", "HIGH", "CRITICAL"]
    ):
        return (
            "Multiple authentication or contextual anomalies "
            "were identified. Further SOC investigation is "
            "recommended."
        )

    # Low-risk case
    if severity == "LOW":
        return (
            "Observed activity is consistent with a "
            "low-risk authentication anomaly with no "
            "strong malicious indicators."
        )

    return (
        "Security-relevant activity was identified and "
        "requires SOC review based on the available evidence."
    )


def generate_findings(
    alert,
    threat_intelligence,
    asset_context,
    risk
):
    """
    Generate structured investigation findings.
    """

    findings = []

    reputation = threat_intelligence.get(
        "reputation",
        "UNKNOWN"
    )

    criticality = asset_context.get(
        "criticality",
        "UNKNOWN"
    )

    if reputation == "MALICIOUS":
        findings.append(
            "Threat intelligence identifies the source IP "
            "as malicious."
        )

    if reputation == "UNKNOWN":
        findings.append(
            "Threat intelligence does not provide a "
            "conclusive reputation for the source IP."
        )

    if alert.get("privileged_account", False):
        findings.append(
            "The incident involves a privileged account."
        )

    if alert.get("impossible_travel", False):
        findings.append(
            "Impossible travel was detected."
        )

    if alert.get("suspicious_process", False):
        findings.append(
            "Suspicious endpoint activity was detected."
        )

    if criticality == "CRITICAL":
        findings.append(
            "The affected asset is classified as critical."
        )

    if alert.get("successful_login", False):
        findings.append(
            "A successful authentication occurred "
            "after the observed login activity."
        )

    if not findings:
        findings.append(
            "No significant security indicators were identified "
            "beyond the original alert."
        )

    return findings


def investigate_incident(alert_id):
    """
    Complete incident investigation workflow.
    """

    result = analyse_alert(alert_id)

    if not result["success"]:
        return {
            "success": False,
            "error": result["error"]
        }

    alert = result["alert"]
    correlation = result["correlation"]
    threat_intelligence = result["threat_intelligence"]
    asset_context = result["asset_context"]
    risk = result["risk"]

    timeline = build_timeline(correlation)

    indicators = identify_indicators(
        alert,
        threat_intelligence,
        asset_context
    )

    findings = generate_findings(
        alert,
        threat_intelligence,
        asset_context,
        risk
    )

    conclusion = determine_investigation_conclusion(
        alert,
        threat_intelligence,
        asset_context,
        risk
    )

    return {
        "success": True,
        "alert_id": alert_id,
        "investigation": {
            "timeline": timeline,
            "indicators": indicators,
            "findings": findings,
            "conclusion": conclusion
        },
        "risk": risk,
        "threat_intelligence": threat_intelligence,
        "asset_context": asset_context
    }


def display_result(result):
    """
    Display investigation results in the terminal.
    """

    if not result["success"]:
        print("\nERROR:")
        print(result["error"])
        return

    investigation = result["investigation"]
    risk = result["risk"]

    print("\n" + "=" * 75)
    print("SENTINELFLOW AI - INCIDENT INVESTIGATION AGENT")
    print("=" * 75)

    print("\n[INCIDENT]")
    print(f"Alert ID: {result['alert_id']}")

    print("\n[RISK CONTEXT]")
    print(f"Risk Score: {risk['risk_score']}/100")
    print(f"Severity: {risk['severity']}")
    print(f"Confidence: {risk['confidence']}")
    print(f"Ambiguous: {risk['ambiguous']}")

    print("\n[INCIDENT TIMELINE]")

    if investigation["timeline"]:
        for event in investigation["timeline"]:
            print(
                f"  {event['timestamp']} | "
                f"{event['event_type']} | "
                f"{event['details']}"
            )
    else:
        print("  No timeline events available.")

    print("\n[SECURITY INDICATORS]")

    if investigation["indicators"]:
        for indicator in investigation["indicators"]:
            print(f"  - {indicator}")
    else:
        print("  - No indicators identified.")

    print("\n[INVESTIGATION FINDINGS]")

    if investigation["findings"]:
        for finding in investigation["findings"]:
            print(f"  - {finding}")
    else:
        print("  - No findings generated.")

    print("\n[INVESTIGATION CONCLUSION]")
    print(f"  {investigation['conclusion']}")

    print("\n[CONTROL STATUS]")

    if risk["human_approval_required"]:
        print("  Human review/approval: REQUIRED")
    else:
        print("  Human review/approval: NOT REQUIRED")

    print(
        "  Automated high-impact action execution: DISABLED"
    )

    print("\n" + "=" * 75)
    print("INCIDENT INVESTIGATION COMPLETE")
    print("=" * 75)


if __name__ == "__main__":

    if len(sys.argv) > 1:
        alert_id = sys.argv[1]
    else:
        alert_id = "INC-1003"

    result = investigate_incident(alert_id)

    display_result(result)