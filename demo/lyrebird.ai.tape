# Lyrebird AI-assisted demo — render with:  vhs demo/lyrebird.ai.tape  (from repo root)
# Produces docs/assets/demo-ai.gif. Requires: vhs, a working lyrebird runtime,
# curl + dig + jq, AND ANTHROPIC_API_KEY exported (a real sk-ant-* key) — the
# recording makes live Claude calls. See demo/README.md.
#
# Two acts:
#   A. The model improvises a believable, INERT reply for an endpoint no static
#      rule anticipated, so an unfamiliar sample keeps talking (tag model-response).
#   B. lyrebird.analyze triages the whole captured session into a structured
#      verdict + indicators + candidate Sigma detections.
# The model is constrained to inert placeholder content — never payloads, scripts,
# or tasking (see models/responder.py and SCOPE.md).
#
# NOTE: keep shell lines free of embedded double-quotes; VHS's Type parser treats
# them as string delimiters. Use single quotes / form-encoding / tail -1 | jq.

Output docs/assets/demo-ai.gif

Set Shell "bash"
Set Theme "Catppuccin Mocha"
Set FontSize 18
Set Width 1320
Set Height 880
Set Padding 22
Set TypingSpeed 45ms

# ---- setup (not recorded; ANTHROPIC_API_KEY is inherited from the environment) ----
Hide
Type "export PS1='$ '"
Enter
Type "export PYTHONPATH=src PYTHONUNBUFFERED=1"
Enter
Type "rm -rf demo/.labdata && clear"
Enter
Show

# ---- stand up the lab with the model layer enabled ----
Type "# Lab with the model layer ON (provider: anthropic) — static rules still win when they match"
Enter
Type "python -m lyrebird --config demo/lyrebird.ai.demo.yaml &"
Enter
Sleep 3s

# ---- ACT A: a sample hits an endpoint no static rule anticipated ----
Type "# A sample calls an endpoint we never wrote a rule for — the model improvises a believable, inert reply"
Enter
Type "curl -s http://localhost:8080/api/v2/telemetry -A 'Mozilla/5.0' -d 'id=bot1&cmd=checkin'; echo"
Enter
Sleep 5s

Type "# That body was model-generated — its event records source=model and the 'model-response' tag"
Enter
Type "tail -1 demo/.labdata/events/demo-ai.jsonl | jq -c '{path: .request.path, source: .response.source, tags}'"
Enter
Sleep 4s

# ---- a little more activity so the triage has something to reason about ----
Type "# A bit more sample activity: a check-in, and a DGA-style DNS lookup"
Enter
Type "curl -s http://localhost:8080/gate.php -d 'id=bot1&data=ZXhmaWw=' >/dev/null; echo sent"
Enter
Sleep 1s
Type "dig +short @127.0.0.1 -p 8053 kq8s7d0fj3nx7zz19a2bdek.example"
Enter
Sleep 1500ms

# ---- ACT B: triage the whole session with the model (live call ~20-25s) ----
Type "# Now triage the captured session — the model turns raw telemetry into a verdict + detection ideas"
Enter
Type "python -m lyrebird.analyze --session demo/.labdata/events/demo-ai.jsonl --provider anthropic --model claude-sonnet-4-6 | jq '{verdict, summary, suggested_detections: [.suggested_detections[].title]}'"
Enter
Sleep 33s

Type "kill %1   # stop the lab"
Enter
Sleep 2s
