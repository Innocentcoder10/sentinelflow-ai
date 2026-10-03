"""
SentinelFlow AI - Governance & Guardrails Framework

Purpose:
Defines the governance controls used to ensure that the AI system
supports SOC analysts without independently executing consequential
security actions.
"""

GOVERNANCE_CONTROLS = [
    {
        "risk": "Incorrect AI risk classification",
        "guardrail": "Deterministic risk scoring + confidence assessment",
        "governance_requirement": "AI risk decisions must be explainable and reviewable",
        "implementation": "Risk Agent calculates score, severity, confidence and contributing indicators"
    },
    {
        "risk": "AI hallucination or unsupported investigation findings",
        "guardrail": "Evidence-grounded analysis",
        "governance_requirement": "AI outputs must be traceable to available evidence",
        "implementation": "Investigation Agent uses correlated alert, threat intelligence and asset context"
    },
    {
        "risk": "Incorrect automated security response",
        "guardrail": "No autonomous consequential actions",
        "governance_requirement": "High-impact actions require human authorization",
        "implementation": "automated_action_allowed is always false"
    },
    {
        "risk": "Ambiguous security alert",
        "guardrail": "Human-in-the-loop review",
        "governance_requirement": "Uncertain cases must be escalated to a human analyst",
        "implementation": "Ambiguous cases are routed to HUMAN_REVIEW"
    },
    {
        "risk": "Critical security incident",
        "guardrail": "Mandatory human approval",
        "governance_requirement": "Critical actions require explicit human authorization",
        "implementation": "CRITICAL cases enter the n8n Wait/HITL workflow"
    },
    {
        "risk": "Unauthorized modification of production systems",
        "guardrail": "Simulation-only response",
        "governance_requirement": "AI must not directly execute production security actions",
        "implementation": "Response Recommendation Agent produces recommendations only"
    },
    {
        "risk": "Loss of investigation traceability",
        "guardrail": "Audit logging",
        "governance_requirement": "Important AI decisions must be auditable",
        "implementation": "n8n records human decisions and governance events in SentinelFlow_Audit_Log"
    },
    {
        "risk": "Incomplete or unreliable input data",
        "guardrail": "Input validation and ambiguity detection",
        "governance_requirement": "AI must identify insufficient evidence",
        "implementation": "Missing or unknown evidence increases ambiguity and triggers human review"
    },
    {
        "risk": "Excessive AI autonomy",
        "guardrail": "Autonomy boundaries",
        "governance_requirement": "AI autonomy must be explicitly controlled",
        "implementation": "A/H/E routing defines Autonomous, Human and Escalation responsibilities"
    },
    {
        "risk": "Sensitive or confidential SOC information",
        "guardrail": "Synthetic/anonymized test data",
        "governance_requirement": "Testing must avoid unauthorized disclosure of sensitive information",
        "implementation": "SentinelFlow demonstration uses synthetic SOC records"
    }
]


def get_governance_controls():
    """Return all governance controls."""
    return GOVERNANCE_CONTROLS


def get_control_summary():
    """Return a compact governance summary."""
    return {
        "total_controls": len(GOVERNANCE_CONTROLS),
        "human_approval_required": True,
        "autonomous_high_impact_actions": False,
        "audit_logging_enabled": True,
        "simulation_only_response": True,
        "synthetic_data_used": True
    }


def display_governance_controls():
    """Print governance controls for CLI testing."""

    print("\n" + "=" * 80)
    print("SENTINELFLOW AI - GOVERNANCE & GUARDRAILS")
    print("=" * 80)

    for i, control in enumerate(GOVERNANCE_CONTROLS, start=1):
        print(f"\nCONTROL {i}")
        print(f"Risk: {control['risk']}")
        print(f"Guardrail: {control['guardrail']}")
        print(f"Governance Requirement: {control['governance_requirement']}")
        print(f"Implementation: {control['implementation']}")

    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)

    summary = get_control_summary()

    for key, value in summary.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    display_governance_controls()