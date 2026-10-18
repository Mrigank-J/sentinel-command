# Sentinel Command

Sentinel Command is a local, synthetic incident-command simulator for security exercises. It never probes hosts, emits network traffic, or integrates with production systems.

## Run

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## What it simulates

- Structured scenarios with assets, evidence, objectives, competing decision lenses, and timed escalation rules.
- Role-based actions for analysts, incident commanders, network responders, and service owners.
- Explicit response prerequisites, state effects, duration, rationale, tradeoffs, and category-level scoring.
- Synthetic evidence streams and an event timeline.
- Live operational readouts for customer impact, exposure, evidence confidence, and coordination load.
- Custom scenario creation and after-action review with missed actions and score breakdowns.

Data is stored locally in `sentinel_command.db`. The legacy `sentinel_drill.db` is retained but is no longer used by the application.
