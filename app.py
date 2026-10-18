from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from uuid import uuid4

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)
DB = Path(app.root_path) / "sentinel_command.db"
ROLES = ["Analyst", "Incident Commander", "Network Responder", "Service Owner"]

SCENARIOS = {
    "port-scan": {
        "name": "External reconnaissance", "severity": "High", "objective": "Limit exposed services and preserve evidence.",
        "assets": ["edge-fw", "web-01", "customer-api"], "initial": ["source-attributed"],
        "evidence": ["Firewall: 198.51.100.42 touched 36 ports in 18 seconds", "IDS: reconnaissance signature matched", "web-01: no authentication failures observed"],
        "escalations": [{"at": 5, "requires": "source-blocked", "event": "Reconnaissance continues; exposed-service risk increased.", "effect": "exposure-increased"}],
        "actions": [
            {"id":"block-source","label":"Block source at perimeter","role":"Network Responder","category":"containment","requires":["source-attributed"],"effects":["source-blocked"],"minutes":2,"points":{"containment":18}},
            {"id":"isolate-web","label":"Isolate web-01","role":"Network Responder","category":"containment","requires":["source-blocked"],"effects":["host-isolated"],"minutes":3,"points":{"containment":10}},
            {"id":"capture-evidence","label":"Preserve firewall and host evidence","role":"Analyst","category":"evidence","requires":["source-attributed"],"effects":["evidence-preserved"],"minutes":4,"points":{"detection":12}},
            {"id":"verify-services","label":"Verify service exposure and close incident","role":"Service Owner","category":"recovery","requires":["source-blocked","evidence-preserved"],"effects":["service-verified"],"minutes":3,"points":{"recovery":15}}
        ]
    },
    "service-saturation": {
        "name": "Service saturation", "severity": "Critical", "objective": "Restore customer API availability while maintaining controls.",
        "assets": ["customer-api", "waf-01", "autoscaler"], "initial": ["traffic-anomaly"],
        "evidence": ["WAF: 4,280 requests/sec from distributed synthetic clients", "APM: p95 latency is 4.3 seconds", "Autoscaler: all current replicas at 92% CPU"],
        "escalations": [{"at":4,"requires":"rate-limited","event":"Availability degraded; checkout dependency timing out.","effect":"availability-degraded"}],
        "actions": [
            {"id":"enable-rate-limit","label":"Enable rate limiting","role":"Network Responder","category":"containment","requires":["traffic-anomaly"],"effects":["rate-limited"],"minutes":2,"points":{"containment":20}},
            {"id":"scale-api","label":"Scale API replicas","role":"Service Owner","category":"recovery","requires":["rate-limited"],"effects":["capacity-restored"],"minutes":4,"points":{"recovery":18}},
            {"id":"record-impact","label":"Record customer impact and notify commander","role":"Incident Commander","category":"communications","requires":["availability-degraded"],"effects":["stakeholders-informed"],"minutes":1,"points":{"communications":8}},
            {"id":"validate-api","label":"Validate API health and close incident","role":"Service Owner","category":"recovery","requires":["rate-limited","capacity-restored"],"effects":["service-verified"],"minutes":2,"points":{"recovery":12}}
        ]
    },
    "credential-stuffing": {
        "name": "Credential-stuffing", "severity": "Medium", "objective": "Protect affected accounts and validate identity controls.",
        "assets": ["identity-provider", "employee-directory", "customer-portal"], "initial": ["suspicious-logins"],
        "evidence": ["Identity: 91 failures across 14 identities", "Risk engine: breached-password pattern found", "Device service: new fingerprint in 13 attempts"],
        "escalations": [{"at":6,"requires":"sessions-challenged","event":"Two accounts now show successful high-risk sign-ins.","effect":"accounts-at-risk"}],
        "actions": [
            {"id":"challenge-sessions","label":"Challenge suspicious sessions","role":"Analyst","category":"containment","requires":["suspicious-logins"],"effects":["sessions-challenged"],"minutes":2,"points":{"containment":16}},
            {"id":"reset-accounts","label":"Reset affected passwords","role":"Service Owner","category":"eradication","requires":["sessions-challenged"],"effects":["credentials-reset"],"minutes":5,"points":{"eradication":18}},
            {"id":"notify-users","label":"Notify affected users","role":"Incident Commander","category":"communications","requires":["credentials-reset"],"effects":["stakeholders-informed"],"minutes":2,"points":{"communications":10}},
            {"id":"verify-identity","label":"Verify identity protection and close incident","role":"Analyst","category":"recovery","requires":["credentials-reset"],"effects":["service-verified"],"minutes":2,"points":{"recovery":12}}
        ]
    }
}

# Enrich each exercise with competing decisions and evolving operational context.
SCENARIOS["port-scan"].update({
    "briefing": {"situation":"Focused reconnaissance targets the public API during a release window; exploitation is not confirmed.","impact":"Unnecessary isolation can interrupt checkout, while delay can enable follow-on access.","unknowns":["Is this an approved assessment?","Which service is being profiled?","Has any host already been accessed?"],"success":["Constrain opportunity","Preserve evidence","Avoid customer harm"]},
    "injects":[{"at":3,"effect":"release-window-confirmed","event":"Change calendar: customer-api routing changed 42 minutes ago."},{"at":7,"effect":"web-anomaly","event":"Web telemetry: unusual requests now target a diagnostic endpoint."}],
    "actions": SCENARIOS["port-scan"]["actions"] + [{"id":"check-change","label":"Check change calendar and ownership","role":"Incident Commander","category":"coordination","requires":["source-attributed"],"effects":["change-context"],"minutes":2,"points":{"communications":8}},{"id":"hunt-web","label":"Hunt web-01 for follow-on activity","role":"Analyst","category":"detection","requires":["evidence-preserved"],"effects":["host-hunted"],"minutes":5,"points":{"detection":14}},{"id":"restrict-diagnostic","label":"Restrict diagnostic endpoint exposure","role":"Service Owner","category":"containment","requires":["web-anomaly"],"effects":["endpoint-restricted"],"minutes":3,"points":{"containment":12}}]
})
SCENARIOS["service-saturation"].update({
    "briefing": {"situation":"API latency rises alongside high-volume traffic. The distributed traffic pattern could be malicious or related to a partner campaign.","impact":"Checkout performance is falling; scaling blindly may increase cost without restoring service.","unknowns":["Is traffic malicious?","Are cache misses involved?","Which journeys are most affected?"],"success":["Restore safely","Limit customer impact","Communicate accurately"]},
    "injects":[{"at":2,"effect":"partner-campaign","event":"Commercial team: a partner email campaign launched this morning."},{"at":6,"effect":"checkout-errors","event":"Synthetics: checkout errors crossed the customer-impact threshold."}],
    "actions": SCENARIOS["service-saturation"]["actions"] + [{"id":"sample-traffic","label":"Sample traffic by client and endpoint","role":"Analyst","category":"detection","requires":["traffic-anomaly"],"effects":["traffic-profiled"],"minutes":3,"points":{"detection":12}},{"id":"enable-cache","label":"Enable safe cache protection for read endpoints","role":"Service Owner","category":"recovery","requires":["traffic-profiled"],"effects":["cache-protected"],"minutes":3,"points":{"recovery":10}},{"id":"publish-status","label":"Publish a customer status update","role":"Incident Commander","category":"communications","requires":["checkout-errors"],"effects":["status-published"],"minutes":2,"points":{"communications":10}}]
})
SCENARIOS["credential-stuffing"].update({
    "briefing": {"situation":"Repeated sign-in failures accompany a smaller number of successful high-risk sessions; the portal remains available.","impact":"Aggressive controls may lock out legitimate staff, while delay risks account takeover and data exposure.","unknowns":["Were high-risk sessions legitimate?","Are passwords reused elsewhere?","Did a third-party breach expose them?"],"success":["Protect sessions","Validate sign-ins","Give users clear guidance"]},
    "injects":[{"at":3,"effect":"vip-account-targeted","event":"Identity telemetry: an executive account is now receiving attempts."},{"at":8,"effect":"download-alert","event":"CASB: a high-risk session accessed a sensitive report."}],
    "actions": SCENARIOS["credential-stuffing"]["actions"] + [{"id":"investigate-session","label":"Investigate successful high-risk sessions","role":"Analyst","category":"detection","requires":["sessions-challenged"],"effects":["sessions-reviewed"],"minutes":5,"points":{"detection":15}},{"id":"protect-vip","label":"Apply additional protection to executive account","role":"Service Owner","category":"containment","requires":["vip-account-targeted"],"effects":["vip-protected"],"minutes":2,"points":{"containment":10}},{"id":"legal-review","label":"Request privacy and legal impact review","role":"Incident Commander","category":"communications","requires":["download-alert"],"effects":["impact-review-started"],"minutes":3,"points":{"communications":12}}]
})

# These are deliberately framed as competing choices rather than a prescribed runbook.
SCENARIOS["port-scan"]["decision_lenses"] = ["Containment may interrupt a legitimate release.", "Evidence is most useful before systems are changed.", "A quiet host is not proof of a safe host."]
SCENARIOS["service-saturation"]["decision_lenses"] = ["Traffic volume alone does not establish intent.", "Capacity can hide a cache or dependency problem.", "A precise customer update is itself a control."]
SCENARIOS["credential-stuffing"]["decision_lenses"] = ["A broad reset protects accounts but creates lockout pressure.", "Successful sessions deserve more attention than failed attempts.", "User communication must not reveal investigation detail."]

ACTION_CONTEXT = {
    "block-source": ("Reduce immediate reachability", "May block an approved scanner or obscure attribution."),
    "isolate-web": ("Stop possible follow-on activity", "Removes a customer-facing host before access is confirmed."),
    "capture-evidence": ("Increase confidence before changing state", "Consumes time while exposure remains available."),
    "verify-services": ("Test that the control actually worked", "Closing early can turn an assumption into the incident record."),
    "check-change": ("Separate change-related noise from hostile activity", "Coordination delays a direct control."),
    "hunt-web": ("Look for evidence of access or persistence", "Investigation time leaves the endpoint exposed."),
    "restrict-diagnostic": ("Remove the newly observed attack surface", "May break release diagnostics during a change window."),
    "enable-rate-limit": ("Protect shared capacity immediately", "Legitimate campaign traffic may be throttled."),
    "scale-api": ("Buy service capacity while learning more", "Adds cost and may amplify a bad dependency pattern."),
    "record-impact": ("Create a shared operational picture", "A premature impact statement can erode trust."),
    "validate-api": ("Prove recovery across the customer path", "Validation takes time after the first green metric."),
    "sample-traffic": ("Distinguish campaign behavior from abuse", "Profiling delays a blunt availability control."),
    "enable-cache": ("Reduce pressure on read-heavy paths", "Stale responses can hide fresh data or dependency failures."),
    "publish-status": ("Give customers an accurate expectation", "Public messaging can increase support load if wrong."),
    "challenge-sessions": ("Interrupt suspicious sessions without resetting everyone", "Challenges can disrupt legitimate users."),
    "reset-accounts": ("Remove a credential that may be reused", "A reset does not prove the active session is gone."),
    "notify-users": ("Help affected users make an informed response", "Specific wording can expose account targeting."),
    "verify-identity": ("Confirm identity controls and session state", "Account recovery is incomplete without checking the control path."),
    "investigate-session": ("Determine whether access became compromise", "Sensitive evidence may require restricted handling."),
    "protect-vip": ("Add targeted friction to a high-value account", "Protects one identity while the wider campaign continues."),
    "legal-review": ("Clarify reporting and privacy obligations", "Review time competes with immediate account protection."),
}

for scenario in SCENARIOS.values():
    for action in scenario["actions"]:
        rationale, tradeoff = ACTION_CONTEXT.get(action["id"], ("Advance the incident objective", "Every control changes the operating picture."))
        action["rationale"] = rationale
        action["tradeoff"] = tradeoff


def connection():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connection() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS scenarios (id TEXT PRIMARY KEY, definition TEXT NOT NULL, custom INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS drills (id TEXT PRIMARY KEY, scenario_id TEXT NOT NULL, role TEXT NOT NULL, started REAL NOT NULL, clock INTEGER NOT NULL, state TEXT NOT NULL);
        """)
        for scenario_id, definition in SCENARIOS.items():
            conn.execute("""INSERT INTO scenarios VALUES (?, ?, 0)
                ON CONFLICT(id) DO UPDATE SET definition = excluded.definition WHERE scenarios.custom = 0""", (scenario_id, json.dumps(definition)))


def scenario_list(conn):
    return [{"id": row["id"], **json.loads(row["definition"]), "custom": bool(row["custom"])} for row in conn.execute("SELECT * FROM scenarios ORDER BY custom, id")]


def load_drill(conn, drill_id):
    row = conn.execute("SELECT * FROM drills WHERE id = ?", (drill_id,)).fetchone()
    if not row:
        return None
    scenario = json.loads(conn.execute("SELECT definition FROM scenarios WHERE id = ?", (row["scenario_id"],)).fetchone()["definition"])
    state = json.loads(row["state"])
    return {"id": row["id"], "scenario_id": row["scenario_id"], "role": row["role"], "clock": row["clock"], "scenario": scenario, **state}


def process_escalations(drill):
    for inject in drill["scenario"].get("injects", []):
        key = inject["effect"]
        if drill["clock"] >= inject["at"] and key not in drill["facts"]:
            drill["facts"].append(key)
            drill["events"].append({"minute": drill["clock"], "kind": "intelligence", "message": inject["event"]})
    for escalation in drill["scenario"].get("escalations", []):
        key = escalation["effect"]
        if drill["clock"] >= escalation["at"] and escalation["requires"] not in drill["facts"] and key not in drill["facts"]:
            drill["facts"].append(key)
            drill["events"].append({"minute": drill["clock"], "kind": "escalation", "message": escalation["event"]})


def score(drill):
    categories = {"detection": 0, "containment": 0, "eradication": 0, "recovery": 0, "communications": 0}
    for result in drill["actions_taken"]:
        if result["success"]:
            for category, points in result["points"].items(): categories[category] += points
    penalties = 10 * sum(event["kind"] == "escalation" for event in drill["events"])
    total = max(0, min(100, sum(categories.values()) - penalties))
    return {"total": total, "categories": categories, "penalties": penalties}


def operational_readout(drill):
    facts = set(drill["facts"])
    events = drill["events"]
    scenario_id = drill["scenario_id"]
    if scenario_id == "service-saturation":
        impact = "High" if "availability-degraded" in facts or "checkout-errors" in facts else "Rising"
        exposure = "Controlled" if "rate-limited" in facts else "Open traffic path"
    elif scenario_id == "credential-stuffing":
        impact = "High" if "accounts-at-risk" in facts or "download-alert" in facts else "Contained so far"
        exposure = "Targeted" if "sessions-challenged" in facts else "Identity surface open"
    else:
        impact = "Elevated" if "exposure-increased" in facts or "web-anomaly" in facts else "Not observed"
        exposure = "Reduced" if "source-blocked" in facts or "endpoint-restricted" in facts else "Public surface open"
    confidence = "High" if "evidence-preserved" in facts or "traffic-profiled" in facts or "sessions-reviewed" in facts else "Developing"
    coordination = "Busy" if len([event for event in events if event["kind"] in ("intelligence", "escalation")]) > 1 else "Watch"
    return {"customer_impact": impact, "exposure": exposure, "evidence_confidence": confidence, "coordination_load": coordination}


def save_drill(conn, drill):
    state = {key: drill[key] for key in ("facts", "events", "actions_taken", "status")}
    conn.execute("UPDATE drills SET clock = ?, state = ? WHERE id = ?", (drill["clock"], json.dumps(state), drill["id"]))


def present(drill):
    actions = []
    completed = {item["id"] for item in drill["actions_taken"]}
    for action in drill["scenario"]["actions"]:
        actions.append({**action, "complete": action["id"] in completed, "eligible": all(item in drill["facts"] for item in action["requires"]), "role_allowed": action["role"] == drill["role"]})
    complete = "service-verified" in drill["facts"]
    phase = "Exercise complete" if complete else "Active incident — assess and decide"
    return {**drill, "available_actions": actions,
            "complete": complete, "phase": phase, "score": score(drill),
            "operational_readout": operational_readout(drill),
            "decision_lenses": drill["scenario"].get("decision_lenses", [])}


@app.get("/")
def index():
    return render_template("index.html", roles=ROLES)


@app.get("/api/scenarios")
def scenarios():
    with connection() as conn:
        return jsonify(scenario_list(conn))


@app.post("/api/scenarios")
def create_scenario():
    data = request.json or {}
    name = str(data.get("name", "")).strip()[:60]
    objective = str(data.get("objective", "")).strip()[:180]
    if not name or not objective:
        return jsonify(error="A scenario needs a name and objective."), 400
    scenario_id = f"custom-{uuid4().hex[:8]}"
    definition = {"name": name, "severity": data.get("severity", "Medium"), "objective": objective, "assets": ["application-01"], "initial": ["alert-received"], "evidence": ["Synthetic alert: custom scenario initiated."], "escalations": [], "actions": [{"id":"triage","label":"Triage and document the alert","role":"Analyst","category":"detection","requires":["alert-received"],"effects":["triage-complete"],"minutes":3,"points":{"detection":10}}, {"id":"contain","label":"Apply containment control","role":"Network Responder","category":"containment","requires":["triage-complete"],"effects":["contained"],"minutes":4,"points":{"containment":15}}, {"id":"verify","label":"Verify recovery and close incident","role":"Service Owner","category":"recovery","requires":["contained"],"effects":["service-verified"],"minutes":3,"points":{"recovery":15}}]}
    with connection() as conn:
        conn.execute("INSERT INTO scenarios VALUES (?, ?, 1)", (scenario_id, json.dumps(definition)))
    return jsonify({"id": scenario_id, **definition, "custom": True}), 201


@app.post("/api/drills")
def start_drill():
    data = request.json or {}
    scenario_id, role = data.get("scenario_id"), data.get("role")
    if role not in ROLES:
        return jsonify(error="Choose a valid exercise role."), 400
    with connection() as conn:
        definition = conn.execute("SELECT definition FROM scenarios WHERE id = ?", (scenario_id,)).fetchone()
        if not definition:
            return jsonify(error="Scenario not found."), 404
        state = {"facts": json.loads(definition["definition"])["initial"], "events": [{"minute": 0, "kind": "alert", "message": "Synthetic incident declared and assigned."}], "actions_taken": [], "status": "Active"}
        drill_id = uuid4().hex
        conn.execute("INSERT INTO drills VALUES (?, ?, ?, ?, ?, ?)", (drill_id, scenario_id, role, time.time(), 0, json.dumps(state)))
        return jsonify(present(load_drill(conn, drill_id))), 201


@app.get("/api/drills/<drill_id>")
def get_drill(drill_id):
    with connection() as conn:
        drill = load_drill(conn, drill_id)
        if not drill: return jsonify(error="Drill not found."), 404
        return jsonify(present(drill))


@app.put("/api/drills/<drill_id>/role")
def change_role(drill_id):
    role = (request.json or {}).get("role")
    if role not in ROLES:
        return jsonify(error="Choose a valid exercise role."), 400
    with connection() as conn:
        if not conn.execute("SELECT 1 FROM drills WHERE id = ?", (drill_id,)).fetchone():
            return jsonify(error="Drill not found."), 404
        conn.execute("UPDATE drills SET role = ? WHERE id = ?", (role, drill_id))
        drill = load_drill(conn, drill_id)
        drill["events"].append({"minute": drill["clock"], "kind": "role", "message": f"Role switched to {role}."})
        save_drill(conn, drill)
        return jsonify(present(drill))


@app.post("/api/drills/<drill_id>/advance")
def advance_drill(drill_id):
    minutes = (request.json or {}).get("minutes", 1)
    if not isinstance(minutes, int) or not 1 <= minutes <= 15:
        return jsonify(error="Advance between 1 and 15 minutes."), 400
    with connection() as conn:
        drill = load_drill(conn, drill_id)
        if not drill: return jsonify(error="Drill not found."), 404
        drill["clock"] += minutes
        process_escalations(drill); save_drill(conn, drill)
        return jsonify(present(drill))


@app.post("/api/drills/<drill_id>/actions/<action_id>")
def execute_action(drill_id, action_id):
    with connection() as conn:
        drill = load_drill(conn, drill_id)
        if not drill: return jsonify(error="Drill not found."), 404
        action = next((item for item in drill["scenario"]["actions"] if item["id"] == action_id), None)
        if not action: return jsonify(error="Action not found."), 404
        if action["role"] != drill["role"]: return jsonify(error=f"This step belongs to the {action['role']} role."), 403
        if any(item["id"] == action_id for item in drill["actions_taken"]): return jsonify(error="Action already executed."), 409
        missing = [item for item in action["requires"] if item not in drill["facts"]]
        if missing:
            drill["actions_taken"].append({"id":action_id,"success":False,"points":{},"message":f"Blocked: prerequisite missing ({', '.join(missing)})."})
        else:
            drill["facts"].extend(item for item in action["effects"] if item not in drill["facts"])
            drill["actions_taken"].append({"id":action_id,"success":True,"points":action["points"],"message":f"Completed by {drill['role']}."})
        drill["clock"] += action["minutes"]
        drill["events"].append({"minute":drill["clock"],"kind":"action","message":f"{action['label']}: {drill['actions_taken'][-1]['message']}"})
        process_escalations(drill)
        if "service-verified" in drill["facts"]: drill["status"] = "Closed"
        save_drill(conn, drill)
        return jsonify(present(drill))


@app.get("/api/drills/<drill_id>/review")
def review(drill_id):
    with connection() as conn:
        drill = load_drill(conn, drill_id)
        if not drill: return jsonify(error="Drill not found."), 404
        data = present(drill)
        missed = [item["label"] for item in data["available_actions"] if not item["complete"] and item["eligible"]]
        findings = ["Escalation occurred before mitigation." if event["kind"] == "escalation" else None for event in drill["events"]]
        findings = [item for item in findings if item] or ["No timed escalation was triggered."]
        return jsonify({"drill": data, "findings": findings, "next_steps": missed or ["All currently eligible actions were completed."]})


init_db()
if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
