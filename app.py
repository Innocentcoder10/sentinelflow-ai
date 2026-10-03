import streamlit as st
import requests

N8N_WEBHOOK_URL = "http://localhost:5678/webhook/sentinelflow-alert"

import sys
from pathlib import Path

# ---------------------------------------------------------
# PROJECT PATH
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------
# IMPORT ORCHESTRATOR
# ---------------------------------------------------------

from core.orchestrator import process_alert

# ---------------------------------------------------------
# IMPORT GOVERNANCE FRAMEWORK
# ---------------------------------------------------------

from governance.governance_framework import (
    get_governance_controls,
    get_control_summary
)


# ---------------------------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------------------------

st.set_page_config(
    page_title="SentinelFlow AI",
    page_icon="🛡️",
    layout="wide"
)


# ---------------------------------------------------------
# HEADER
# ---------------------------------------------------------

st.title("🛡️ SentinelFlow AI")

st.subheader(
    "Governed Agentic AI for SOC Alert Triage & Incident Investigation"
)

st.markdown(
    """
    **AI investigates and recommends — humans retain control
    over consequential security actions.**
    """
)

st.divider()


# ---------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------

st.sidebar.title("SOC Control Panel")

st.sidebar.markdown(
    """
    ### SentinelFlow AI

    Governed Agentic AI system for:

    - Alert correlation
    - Threat intelligence
    - Asset context
    - Risk prioritisation
    - Incident investigation
    - Response recommendation
    - Human-in-the-loop escalation
    """
)

st.sidebar.divider()

st.sidebar.caption(
    "Synthetic security data only. "
    "No production security actions are executed."
)


# ---------------------------------------------------------
# INCIDENT SELECTION
# ---------------------------------------------------------

st.header("🔍 SOC Alert Investigation")

alert_id = st.selectbox(
    "Select a synthetic SOC alert",
    [
        "INC-1001",
        "INC-1002",
        "INC-1003"
    ]
)

analyse_button = st.button(
    "🚀 Analyse Alert",
    type="primary"
)


# ---------------------------------------------------------
# ANALYSIS
# ---------------------------------------------------------

if analyse_button:

    with st.spinner(
        "SentinelFlow AI is investigating the alert..."
    ):

        # -------------------------------------------------
        # TRIGGER n8n WORKFLOW
        # -------------------------------------------------

        try:

            n8n_response = requests.post(
                N8N_WEBHOOK_URL,
                json={"alert_id": alert_id},
                timeout=5
            )

            n8n_triggered = n8n_response.status_code == 200

        except requests.RequestException:

            n8n_triggered = False

        # -------------------------------------------------
        # RUN EXISTING SENTINELFLOW ANALYSIS
        # -------------------------------------------------

        result = process_alert(
            alert_id
        )

    if not result["success"]:

        st.error(
            f"Investigation failed: {result['error']}"
        )

    else:

        # -------------------------------------------------
        # STORE RESULT
        # -------------------------------------------------

        st.session_state["analysis_result"] = result

        # Store n8n trigger status
        st.session_state["n8n_triggered"] = n8n_triggered


# ---------------------------------------------------------
# DISPLAY RESULTS
# ---------------------------------------------------------

if "analysis_result" in st.session_state:

    result = st.session_state["analysis_result"]

    risk = result["risk"]

    routing = result["routing"]

    investigation = result["investigation"]

    response = result["response"]

    alert = result["alert"]

    threat_intelligence = result[
        "threat_intelligence"
    ]

    asset_context = result[
        "asset_context"
    ]

    # -----------------------------------------------------
    # n8n STATUS
    # -----------------------------------------------------

    if st.session_state.get("n8n_triggered", False):

        st.success(
            "🔗 n8n orchestration workflow triggered successfully."
        )

    else:

        st.warning(
            "⚠️ n8n workflow could not be triggered. "
            "The local SentinelFlow analysis was still completed."
        )

    # -----------------------------------------------------
    # INCIDENT INFORMATION
    # -----------------------------------------------------

    st.divider()

    st.header("📋 Incident Overview")

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "Alert ID",
            result["alert_id"]
        )

    with col2:

        st.metric(
            "User",
            alert["user"]
        )

    with col3:

        st.metric(
            "Source IP",
            alert["source_ip"]
        )

    with col4:

        st.metric(
            "Asset",
            alert["destination_asset"]
        )

    st.write(
        f"**Alert:** {alert['alert_name']}"
    )

    st.write(
        f"**Description:** {alert['description']}"
    )

    # -----------------------------------------------------
    # RISK DASHBOARD
    # -----------------------------------------------------

    st.divider()

    st.header("🎯 Risk Assessment")

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.metric(
            "Risk Score",
            f"{risk['risk_score']}/100"
        )

    with col2:

        st.metric(
            "Severity",
            risk["severity"]
        )

    with col3:

        st.metric(
            "Confidence",
            risk["confidence"]
        )

    with col4:

        st.metric(
            "Ambiguous",
            "YES" if risk["ambiguous"] else "NO"
        )

    # -----------------------------------------------------
    # RISK FACTORS
    # -----------------------------------------------------

    st.subheader("Key Risk Factors")

    if risk["reasons"]:

        for reason in risk["reasons"]:

            st.write(
                f"• {reason}"
            )

    else:

        st.write(
            "No major risk factors identified."
        )

    # -----------------------------------------------------
    # EVIDENCE
    # -----------------------------------------------------

    st.divider()

    st.header("🔎 Evidence & Context")

    col1, col2 = st.columns(2)

    with col1:

        st.subheader("Threat Intelligence")

        st.write(
            f"**IP:** {alert['source_ip']}"
        )

        st.write(
            f"**Reputation:** "
            f"{threat_intelligence['reputation']}"
        )

        st.write(
            f"**Confidence:** "
            f"{threat_intelligence['confidence']}"
        )

        st.write(
            f"**Source:** "
            f"{threat_intelligence['source']}"
        )

    with col2:

        st.subheader("Asset Context")

        st.write(
            f"**Asset:** "
            f"{asset_context['asset']}"
        )

        st.write(
            f"**Type:** "
            f"{asset_context['asset_type']}"
        )

        st.write(
            f"**Criticality:** "
            f"{asset_context['criticality']}"
        )

        st.write(
            f"**Environment:** "
            f"{asset_context['environment']}"
        )

    # -----------------------------------------------------
    # INCIDENT INVESTIGATION
    # -----------------------------------------------------

    st.divider()

    st.header("🕵️ Incident Investigation")

    st.subheader(
        "Investigation Conclusion"
    )

    st.info(
        investigation["conclusion"]
    )

    st.subheader(
        "Security Indicators"
    )

    for indicator in investigation[
        "indicators"
    ]:

        st.write(
            f"• {indicator}"
        )

    st.subheader(
        "Investigation Findings"
    )

    for finding in investigation[
        "findings"
    ]:

        st.write(
            f"• {finding}"
        )

    # -----------------------------------------------------
    # TIMELINE
    # -----------------------------------------------------

    st.subheader(
        "Incident Timeline"
    )

    timeline = investigation[
        "timeline"
    ]

    if timeline:

        for event in timeline:

            st.write(
                f"**{event['timestamp']}** — "
                f"{event['event_type']} — "
                f"{event['details']}"
            )

    else:

        st.write(
            "No timeline events available."
        )

    # -----------------------------------------------------
    # RESPONSE
    # -----------------------------------------------------

    st.divider()

    st.header("🚨 Response Recommendation")

    st.write(
        f"**Priority:** "
        f"{response['priority']}"
    )

    for index, recommendation in enumerate(
        response["recommendations"],
        start=1
    ):

        st.write(
            f"**{index}.** {recommendation}"
        )

    # -----------------------------------------------------
    # GOVERNANCE FOR CURRENT INCIDENT
    # -----------------------------------------------------

    st.divider()

    st.header("🛡️ Governance & Human Oversight")

    col1, col2, col3 = st.columns(3)

    with col1:

        if routing["human_required"]:

            st.error(
                "👤 HUMAN REVIEW REQUIRED"
            )

        else:

            st.success(
                "👤 HUMAN REVIEW NOT REQUIRED"
            )

    with col2:

        st.info(
            f"Routing: {routing['route']}"
        )

    with col3:

        st.warning(
            "Automated high-impact actions are disabled."
        )

    st.write(
        f"**Routing Reason:** "
        f"{routing['reason']}"
    )

    # -----------------------------------------------------
    # FINAL DECISION
    # -----------------------------------------------------

    st.divider()

    st.header("📌 Final SOC Decision")

    if routing["route"] == "SECURITY_ESCALATION":

        st.error(
            "🔴 CRITICAL INCIDENT — "
            "SECURITY ESCALATION REQUIRED"
        )

    elif routing["route"] == "SOC_ESCALATION":

        st.warning(
            "🟠 HIGH-RISK INCIDENT — "
            "SOC ESCALATION REQUIRED"
        )

    elif routing["route"] == "HUMAN_REVIEW":

        st.warning(
            "🟡 AMBIGUOUS INCIDENT — "
            "HUMAN REVIEW REQUIRED"
        )

    elif routing["route"] == "SOC_ANALYST_REVIEW":

        st.warning(
            "🟡 MEDIUM-RISK INCIDENT — "
            "SOC ANALYST REVIEW REQUIRED"
        )

    else:

        st.success(
            "🟢 LOW-RISK ALERT — "
            "CONTINUE MONITORING"
        )


# ---------------------------------------------------------
# GOVERNANCE FRAMEWORK
# ---------------------------------------------------------

st.divider()

st.header("🛡️ Governance & Guardrails")

st.markdown(
    """
    **SentinelFlow AI follows a governed-agentic approach:**

    > AI investigates and recommends. Humans retain control over
    consequential security decisions.
    """
)

summary = get_control_summary()

col1, col2, col3, col4 = st.columns(4)

with col1:

    st.metric(
        "Governance Controls",
        summary["total_controls"]
    )

with col2:

    st.metric(
        "Human Approval",
        "REQUIRED"
        if summary["human_approval_required"]
        else "NOT REQUIRED"
    )

with col3:

    st.metric(
        "Autonomous High-Impact Actions",
        "DISABLED"
        if not summary["autonomous_high_impact_actions"]
        else "ENABLED"
    )

with col4:

    st.metric(
        "Audit Logging",
        "ENABLED"
        if summary["audit_logging_enabled"]
        else "DISABLED"
    )

st.subheader(
    "Risk → Guardrail → Governance → Implementation"
)

controls = get_governance_controls()

for index, control in enumerate(controls, start=1):

    with st.expander(
        f"Control {index}: {control['risk']}"
    ):

        st.markdown(
            f"**Risk:** {control['risk']}"
        )

        st.markdown(
            f"**Guardrail:** {control['guardrail']}"
        )

        st.markdown(
            f"**Governance Requirement:** "
            f"{control['governance_requirement']}"
        )

        st.markdown(
            f"**Implementation:** "
            f"{control['implementation']}"
        )

st.success(
    "🛡️ SentinelFlow AI is designed as a human-governed "
    "SOC decision-support system. Consequential security "
    "actions are not executed autonomously."
)


# ---------------------------------------------------------
# INITIAL STATE
# ---------------------------------------------------------

if "analysis_result" not in st.session_state:

    st.info(
        "Select a synthetic SOC alert above and click "
        "**Analyse Alert** to begin the investigation."
    )


# ---------------------------------------------------------
# FOOTER
# ---------------------------------------------------------

st.divider()

st.caption(
    "SentinelFlow AI | Governed Agentic SOC Decision Support | "
    "Synthetic Data | Human Oversight Enabled"
)