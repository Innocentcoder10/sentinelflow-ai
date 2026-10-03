import sys
from pathlib import Path

# Import our existing agents
from agents.alert_correlation import correlate_alert
from agents.threat_intelligence import investigate_ip
from agents.asset_context import investigate_asset


# ============================================================
# SENTINELFLOW AI
# Risk & Prioritisation Agent
# ============================================================


# ============================================================
# RISK CALCULATION
# ============================================================

def calculate_risk(alert_data, threat_data, asset_data):
    """
    Calculate a risk score using the correlated security evidence.

    This is a deterministic risk engine.
    The score is based on observable evidence rather than
    allowing an LLM to invent a security score.

    The function also detects ambiguous cases where evidence
    is incomplete or uncertain.
    """

    score = 0

    reasons = []

    # ========================================================
    # 1. Failed login activity
    # ========================================================

    failed_logins = alert_data.get("failed_login_count", 0)

    if failed_logins >= 10:

        score += 20

        reasons.append(
            f"High number of failed login attempts ({failed_logins})"
        )

    elif failed_logins >= 5:

        score += 10

        reasons.append(
            f"Elevated failed login attempts ({failed_logins})"
        )

    elif failed_logins > 0:

        score += 5

        reasons.append(
            f"Failed login activity detected ({failed_logins})"
        )

    # ========================================================
    # 2. Successful login
    # ========================================================

    if alert_data.get("successful_login", False):

        score += 10

        reasons.append(
            "Successful login occurred after authentication failures"
        )

    # ========================================================
    # 3. Privileged account
    # ========================================================

    if alert_data.get("privileged_account", False):

        score += 20

        reasons.append(
            "Privileged account involved"
        )

    # ========================================================
    # 4. Impossible travel
    # ========================================================

    if alert_data.get("impossible_travel", False):

        score += 15

        reasons.append(
            "Impossible-travel condition detected"
        )

    # ========================================================
    # 5. Suspicious endpoint process
    # ========================================================

    if alert_data.get("suspicious_process", False):

        score += 15

        reasons.append(
            "Suspicious endpoint process detected"
        )

    # ========================================================
    # 6. Threat intelligence
    # ========================================================

    reputation = threat_data.get("reputation", "UNKNOWN")

    if reputation == "MALICIOUS":

        score += 25

        reasons.append(
            "Source IP has malicious threat intelligence reputation"
        )

    elif reputation == "UNKNOWN":

        # Unknown intelligence does NOT mean malicious.
        # We add only a small uncertainty factor.

        score += 5

        reasons.append(
            "Threat intelligence reputation is unknown"
        )

    # ========================================================
    # 7. Asset criticality
    # ========================================================

    criticality = asset_data.get("criticality", "UNKNOWN")

    if criticality == "CRITICAL":

        score += 20

        reasons.append(
            "Affected asset is classified as CRITICAL"
        )

    elif criticality == "MEDIUM":

        score += 10

        reasons.append(
            "Affected asset has MEDIUM criticality"
        )

    elif criticality == "LOW":

        score += 3

        reasons.append(
            "Affected asset has LOW criticality"
        )

    # ========================================================
    # 8. Cap score at 100
    # ========================================================

    score = min(score, 100)

    # ========================================================
    # 9. Determine initial severity
    # ========================================================

    if score >= 80:

        severity = "CRITICAL"

    elif score >= 60:

        severity = "HIGH"

    elif score >= 35:

        severity = "MEDIUM"

    else:

        severity = "LOW"

    # ========================================================
    # 10. Determine initial escalation
    # ========================================================

    if severity == "CRITICAL":

        escalation = "REQUIRED"
        human_approval = True

    elif severity == "HIGH":

        escalation = "REQUIRED"
        human_approval = True

    elif severity == "MEDIUM":

        escalation = "ANALYST_REVIEW"
        human_approval = True

    else:

        escalation = "NOT_REQUIRED"
        human_approval = False

    # ========================================================
    # 11. Ambiguity Detection
    # ========================================================

    ambiguous = False

    ambiguity_reasons = []

    # --------------------------------------------------------
    # Unknown threat intelligence
    # --------------------------------------------------------

    if reputation == "UNKNOWN":

        ambiguous = True

        ambiguity_reasons.append(
            "Threat intelligence evidence is inconclusive"
        )

    # --------------------------------------------------------
    # Unknown asset criticality
    # --------------------------------------------------------

    if criticality == "UNKNOWN":

        ambiguous = True

        ambiguity_reasons.append(
            "Asset criticality is unknown"
        )

    # --------------------------------------------------------
    # Missing successful authentication evidence
    # --------------------------------------------------------

    if not alert_data.get("successful_login", False):

        ambiguous = True

        ambiguity_reasons.append(
            "No successful authentication event confirmed"
        )

    # --------------------------------------------------------
    # Missing endpoint evidence
    # --------------------------------------------------------

    if "suspicious_process" not in alert_data:

        ambiguous = True

        ambiguity_reasons.append(
            "Endpoint process evidence is incomplete"
        )

    # ========================================================
    # 12. Apply ambiguity override
    # ========================================================

    if ambiguous:

        # An ambiguous case must go to a human.
        escalation = "HUMAN_REVIEW"

        human_approval = True

        # Do not allow an ambiguous case to remain LOW.
        if severity == "LOW":

            severity = "MEDIUM"

    # ========================================================
    # 13. Confidence
    # ========================================================

    confidence_factors = 0

    if alert_data:

        confidence_factors += 1

    if reputation != "UNKNOWN":

        confidence_factors += 1

    if criticality != "UNKNOWN":

        confidence_factors += 1

    if confidence_factors == 3:

        confidence = "HIGH"

    elif confidence_factors == 2:

        confidence = "MEDIUM"

    else:

        confidence = "LOW"

    # ========================================================
    # 14. Final result
    # ========================================================

    return {
        "risk_score": score,
        "severity": severity,
        "confidence": confidence,
        "escalation": escalation,
        "human_approval_required": human_approval,
        "ambiguous": ambiguous,
        "ambiguity_reasons": ambiguity_reasons,
        "reasons": reasons
    }


# ============================================================
# RUN RISK ANALYSIS
# ============================================================

def analyse_alert(alert_id):
    """
    Run the complete evidence and risk analysis workflow.
    """

    # ========================================================
    # Step 1 — Correlate alert
    # ========================================================

    correlation = correlate_alert(alert_id)

    if not correlation["success"]:

        return {
            "success": False,
            "error": correlation["error"]
        }

    # ========================================================
    # Step 2 — Extract source IP
    # ========================================================

    source_ip = correlation["source_ip"]

    # ========================================================
    # Step 3 — Threat intelligence
    # ========================================================

    threat_data = investigate_ip(source_ip)

    # ========================================================
    # Step 4 — Asset context
    # ========================================================

    destination_asset = correlation["destination_asset"]

    asset_data = investigate_asset(destination_asset)

    # ========================================================
    # Step 5 — Calculate risk
    # ========================================================

    risk_result = calculate_risk(
        correlation["alert"],
        threat_data,
        asset_data
    )

    # ========================================================
    # Step 6 — Combine everything
    # ========================================================

    return {
        "success": True,
        "alert_id": alert_id,
        "alert": correlation["alert"],
        "correlation": correlation,
        "threat_intelligence": threat_data,
        "asset_context": asset_data,
        "risk": risk_result
    }


# ============================================================
# DISPLAY RISK RESULT
# ============================================================

def display_result(result):

    # --------------------------------------------------------
    # Error handling
    # --------------------------------------------------------

    if not result["success"]:

        print("\nERROR:")
        print(result["error"])
        return

    risk = result["risk"]

    # ========================================================
    # Header
    # ========================================================

    print("\n" + "=" * 70)

    print(
        "SENTINELFLOW AI - "
        "RISK & PRIORITISATION AGENT"
    )

    print("=" * 70)

    # ========================================================
    # Incident
    # ========================================================

    print("\n[INCIDENT]")

    print(
        f"Alert ID: "
        f"{result['alert_id']}"
    )

    print(
        f"Alert: "
        f"{result['alert']['alert_name']}"
    )

    # ========================================================
    # Risk result
    # ========================================================

    print("\n[RISK ASSESSMENT]")

    print(
        f"Risk Score: "
        f"{risk['risk_score']}/100"
    )

    print(
        f"Severity: "
        f"{risk['severity']}"
    )

    print(
        f"Confidence: "
        f"{risk['confidence']}"
    )

    print(
        f"Ambiguous Case: "
        f"{risk['ambiguous']}"
    )

    # ========================================================
    # Escalation
    # ========================================================

    print("\n[ESCALATION DECISION]")

    print(
        f"Escalation: "
        f"{risk['escalation']}"
    )

    print(
        "Human Approval Required: "
        f"{risk['human_approval_required']}"
    )

    # ========================================================
    # Key risk factors
    # ========================================================

    print("\n[KEY RISK FACTORS]")

    if risk["reasons"]:

        for reason in risk["reasons"]:

            print(
                f"  - {reason}"
            )

    else:

        print(
            "  - No major risk factors identified."
        )

    # ========================================================
    # Ambiguity reasons
    # ========================================================

    if risk["ambiguous"]:

        print("\n[AMBIGUITY REASONS]")

        for reason in risk["ambiguity_reasons"]:

            print(
                f"  - {reason}"
            )

    # ========================================================
    # Final decision
    # ========================================================

    print("\n[FINAL DECISION]")

    if risk["ambiguous"]:

        print(
            "🟡 AMBIGUOUS / INSUFFICIENT EVIDENCE"
        )

        print(
            "Human SOC analyst review is required."
        )

        print(
            "The system will not independently "
            "execute a high-impact response."
        )

    elif risk["severity"] == "CRITICAL":

        print(
            "🔴 CRITICAL SECURITY INCIDENT"
        )

        print(
            "Immediate escalation is required."
        )

        print(
            "Human approval is required before "
            "high-impact actions."
        )

    elif risk["severity"] == "HIGH":

        print(
            "🟠 HIGH-RISK SECURITY INCIDENT"
        )

        print(
            "SOC escalation is required."
        )

        print(
            "Human review is required."
        )

    elif risk["severity"] == "MEDIUM":

        print(
            "🟡 MEDIUM-RISK SECURITY INCIDENT"
        )

        print(
            "SOC analyst review is recommended."
        )

    else:

        print(
            "🟢 LOW-RISK SECURITY ALERT"
        )

        print(
            "No immediate escalation is required."
        )

    # ========================================================
    # Footer
    # ========================================================

    print("\n" + "=" * 70)

    print(
        "RISK ANALYSIS COMPLETE"
    )

    print("=" * 70)


# ============================================================
# MAIN PROGRAM
# ============================================================

if __name__ == "__main__":

    # --------------------------------------------------------
    # Allow alert ID from terminal.
    #
    # Examples:
    #
    # python agents/risk_agent.py INC-1001
    # python agents/risk_agent.py INC-1002
    # python agents/risk_agent.py INC-1003
    # --------------------------------------------------------

    if len(sys.argv) > 1:

        alert_id = sys.argv[1]

    else:

        # Default test case
        alert_id = "INC-1003"

    # --------------------------------------------------------
    # Run analysis
    # --------------------------------------------------------

    result = analyse_alert(alert_id)

    # --------------------------------------------------------
    # Display result
    # --------------------------------------------------------

    display_result(result)