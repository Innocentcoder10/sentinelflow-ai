# SentinelFlow AI
## AS-IS → TO-BE Process, A/H/E Mapping & System Architecture

---

# 1. Problem Statement

Traditional SOC alert triage can involve manual correlation of alerts,
authentication events, endpoint activity, threat intelligence and asset
context before an analyst determines severity and response.

SentinelFlow AI provides governed agentic decision support for this process.

The system investigates alerts, correlates evidence, assesses risk,
recommends response actions and routes decisions according to predefined
autonomy and human-approval boundaries.

The system does NOT autonomously execute consequential security actions.

---

# 2. AS-IS Process

## Traditional SOC Alert Investigation

```text
Security Alert
      |
      v
SOC Analyst Receives Alert
      |
      v
Collect Authentication Logs
      |
      v
Check Endpoint Activity
      |
      v
Check Threat Intelligence
      |
      v
Check Asset Criticality
      |
      v
Correlate Evidence
      |
      v
Assess Risk
      |
      v
Investigate Incident
      |
      v
Determine Response
      |
      v
Escalate / Respond
      |
      v
Record Investigation

AS-IS Characteristics
Manual evidence collection
Multiple sources must be checked
Analyst performs correlation
Risk assessment requires analyst effort
Ambiguous cases require additional investigation
Critical cases require security escalation
Investigation documentation is performed manually
3. TO-BE Process
SentinelFlow AI Governed Agentic Workflow
Synthetic SOC Alert
        |
        v
   Streamlit UI
        |
        v
    n8n Webhook
        |
        v
    FastAPI API
        |
        v
Alert Correlation Agent
        |
        +----------------------+
        |                      |
        v                      v
Threat Intelligence      Asset Context
     Agent                    Agent
        |                      |
        +----------+-----------+
                   |
                   v
              Risk Agent
                   |
                   v
        Incident Investigation
                   |
                   v
        Response Recommendation
                   |
                   v
             n8n Routing
                   |
       +-----------+-----------+
       |           |           |
       v           v           v
      LOW       MEDIUM      HIGH/CRITICAL
       |           |           |
       v           v           v
    Monitor    Human Review  Escalation
                               |
                               v
                         Human Approval
                               |
                      +--------+--------+
                      |                 |
                      v                 v
                   APPROVE           REJECT
                      |                 |
                      +--------+--------+
                               |
                               v
                          Audit Log
4. Agent Responsibilities
4.1 Alert Correlation Agent
Purpose

Correlates the incoming alert with authentication logs, endpoint logs, threat intelligence and asset information.

Responsibilities
Collect relevant evidence
Correlate authentication activity
Correlate endpoint activity
Connect alert information with threat intelligence
Connect alert information with asset context
Output
Correlated alert information
Authentication evidence
Endpoint evidence
Threat intelligence evidence
Asset context
4.2 Threat Intelligence Agent
Purpose

Evaluates the reputation of the source IP using the synthetic threat intelligence dataset.

Possible Outputs
BENIGN
UNKNOWN
MALICIOUS
Additional Output
Threat intelligence confidence
Threat intelligence source
4.3 Asset Context Agent
Purpose

Determines the importance and environment of the affected asset.

Criticality Levels
LOW
MEDIUM
CRITICAL
Output
Asset name
Asset type
Criticality
Owner
Environment
4.4 Risk Agent
Purpose

Calculates a deterministic risk score based on security indicators.

Inputs
Failed login count
Successful login
Privileged account status
Impossible travel
Suspicious process
Threat intelligence reputation
Asset criticality
Outputs
Risk score
Severity
Confidence
Risk reasons
Ambiguity status
Escalation requirement
Human approval requirement
4.5 Incident Investigation Agent
Purpose

Builds an investigation summary using the correlated evidence.

Outputs
Incident timeline
Security indicators
Investigation findings
Investigation conclusion
Human review status
4.6 Response Recommendation Agent
Purpose

Produces recommended security response actions based on the investigation and risk assessment.

Governance Boundary

The agent recommends actions but does not execute consequential production security actions.

All response actions are recommendation/simulation only.

5. A/H/E Mapping
A = Autonomous

The following activities can operate automatically:

Activity	Mode	Reason
Alert intake	A	Low-impact processing
Alert correlation	A	Evidence aggregation
Threat intelligence lookup	A	Information enrichment
Asset context lookup	A	Context enrichment
Initial risk scoring	A	Deterministic assessment
Investigation timeline generation	A	Decision-support activity
Investigation summary	A	Analyst assistance
Response recommendation	A	Recommendation only
6. H = Human-in-the-Loop

The following activities require human involvement:

Activity	Mode	Reason
Ambiguous alert review	H	Evidence is insufficient or uncertain
Medium-risk analyst review	H	Analyst validation required
Critical response approval	H	Consequential security decision
Final response authorization	H	Human retains control
7. E = Escalation

Escalation occurs when the system identifies significant security risk.

Condition	Escalation
HIGH severity	SOC escalation
CRITICAL severity	Security escalation
Ambiguous evidence	Human review
Critical privileged-account compromise	Security escalation
8. Autonomy Boundary

SentinelFlow AI follows the principle:

AI investigates and recommends. Humans retain control over consequential security actions.

The system does not autonomously:

Disable user accounts
Block production systems
Modify firewall rules
Delete data
Terminate production processes
Execute containment actions
Make irreversible security changes

All response actions are recommendation/simulation only.

9. Routing Logic
                    Risk Assessment
                           |
             +-------------+-------------+
             |             |             |
             v             v             v
           LOW          MEDIUM       HIGH/CRITICAL
             |             |             |
             v             v             v
          MONITOR     HUMAN REVIEW    ESCALATION
                                           |
                                           v
                                    Human Approval
                                           |
                                  +--------+--------+
                                  |                 |
                                  v                 v
                               APPROVE           REJECT
                                  |                 |
                                  +--------+--------+
                                           |
                                           v
                                      Audit Log
10. Three Synthetic Test Scenarios
10.1 INC-1001 — Normal
Expected Classification
Risk Score: 18
Severity: LOW
Routing: MONITOR
Human Approval: NOT REQUIRED
Automated Action: DISABLED
Purpose

Demonstrates normal low-risk alert processing.

10.2 INC-1002 — Ambiguous
Expected Classification
Risk Score: 45
Severity: MEDIUM
Routing: HUMAN_REVIEW
Human Approval: REQUIRED
Automated Action: DISABLED
Reason

Threat intelligence is unknown and the evidence contains ambiguity requiring analyst review.

Purpose

Demonstrates human-in-the-loop handling.

10.3 INC-1003 — High Risk
Expected Classification
Risk Score: 100
Severity: CRITICAL
Routing: SECURITY_ESCALATION
Human Approval: REQUIRED
Automated Action: DISABLED
Purpose

Demonstrates critical incident escalation and mandatory human authorization.

11. Governance Controls

SentinelFlow AI implements the following controls:

Deterministic risk scoring
Confidence assessment
Evidence-grounded investigation
Ambiguity detection
Human-in-the-loop review
Mandatory approval for critical cases
Simulation-only response
Audit logging
Explicit autonomy boundaries
Synthetic/anonymized demonstration data
12. Auditability

Important governance events are recorded in:

SentinelFlow_Audit_Log

The audit information includes:

Alert ID
Severity
Decision
Human approval requirement
Automated action permission
Audit event
Execution mode
13. AS-IS vs TO-BE Comparison
Dimension	AS-IS	TO-BE: SentinelFlow AI
Alert intake	Manual analyst handling	Streamlit + n8n workflow
Evidence collection	Manual	Agent-assisted
Alert correlation	Manual	Correlation Agent
Threat intelligence	Manual lookup	Threat Intelligence Agent
Asset context	Manual lookup	Asset Context Agent
Risk assessment	Analyst assessment	Risk Agent
Investigation	Manual investigation	Investigation Agent
Response decision	Analyst-driven	AI recommendation + governed routing
Ambiguous cases	Analyst investigation	Human-in-the-loop
Critical cases	Manual escalation	Automated escalation routing + HITL
High-impact action	Analyst-controlled	Autonomous execution disabled
Audit trail	Manual documentation	n8n audit logging
Test data	Operational/security data	Synthetic demonstration data
14. Overall System Architecture
                         SENTINELFLOW AI
                                |
                                v
                       +----------------+
                       |  Streamlit UI  |
                       +-------+--------+
                               |
                               v
                       +----------------+
                       | n8n Orchestrator|
                       +-------+--------+
                               |
                               v
                       +----------------+
                       |    FastAPI     |
                       +-------+--------+
                               |
             +-----------------+------------------+
             |                 |                  |
             v                 v                  v
      +-------------+   +-------------+   +-------------+
      | Correlation |   | Threat Intel|   | Asset       |
      |    Agent    |   |    Agent    |   | Context     |
      +------+------+   +------+------+   | Agent       |
             |                 |           +------+------+
             |                 |                  |
             +-----------------+------------------+
                               |
                               v
                       +---------------+
                       |   Risk Agent  |
                       +-------+-------+
                               |
                               v
                  +-------------------------+
                  | Investigation Agent     |
                  +------------+------------+
                               |
                               v
                  +-------------------------+
                  | Response Recommendation|
                  +------------+------------+
                               |
                               v
                        n8n Routing
                               |
              +----------------+----------------+
              |                |                |
              v                v                v
            LOW             MEDIUM        HIGH/CRITICAL
              |                |                |
              v                v                v
          MONITOR        HUMAN REVIEW       ESCALATION
                                                |
                                                v
                                         Human Approval
                                                |
                                                v
                                           Audit Log
15. End-to-End Data Flow
1. SOC alert selected in Streamlit
                |
                v
2. Alert sent to n8n webhook
                |
                v
3. n8n calls SentinelFlow FastAPI
                |
                v
4. Correlation Agent gathers evidence
                |
                v
5. Threat Intelligence Agent enriches IP
                |
                v
6. Asset Context Agent enriches asset
                |
                v
7. Risk Agent calculates risk
                |
                v
8. Investigation Agent generates findings
                |
                v
9. Response Agent generates recommendation
                |
                v
10. n8n applies governance routing
                |
       +--------+--------+
       |        |        |
       v        v        v
      LOW    MEDIUM    CRITICAL/HIGH
       |        |        |
       v        v        v
    Monitor  Review   Escalation
                         |
                         v
                   Human Approval
                         |
                         v
                     Audit Log
16. Governance Decision Principle

SentinelFlow AI is designed as a governed SOC decision-support system rather than an autonomous security-response system.

The objective is to reduce repetitive investigation effort while maintaining:

Human oversight
Explainability
Evidence traceability
Controlled autonomy
Escalation
Auditability
Safe response boundaries
17. Implementation Status

The current proof of concept demonstrates:

Streamlit SOC interface
n8n orchestration
FastAPI backend
Alert correlation
Threat intelligence enrichment
Asset context enrichment
Deterministic risk scoring
Incident investigation
Response recommendation
LOW/MEDIUM/HIGH/CRITICAL routing
Human approval workflow for critical cases
Audit logging
Governance and guardrail framework
Synthetic SOC test scenarios
INC-1001 → LOW → MONITOR

INC-1002 → MEDIUM → HUMAN_REVIEW

INC-1003 → CRITICAL → SECURITY_ESCALATION → HUMAN_APPROVAL
18. Core Design Principle

AI investigates and recommends. Humans retain control over consequential security actions.

SentinelFlow AI therefore combines agentic investigation with explicit governance, human oversight, escalation controls and auditability.