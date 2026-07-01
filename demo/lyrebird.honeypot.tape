# Lyrebird honeypot demo — render with:  vhs demo/lyrebird.honeypot.tape  (from repo root)
# Produces docs/assets/demo-honeypot.gif. Prerequisites: vhs, a working lyrebird
# runtime (python deps installed), and jq.
#
# The "sample" is a benign python client standing in for a Mirai-style bot —
# Lyrebird only observes; it never executes or fetches anything.

Output docs/assets/demo-honeypot.gif

Set Shell "bash"
Set Theme "Catppuccin Mocha"
Set FontSize 18
Set Width 1320
Set Height 820
Set Padding 22
Set TypingSpeed 45ms

# ---- setup (not recorded) ----
Hide
Type "source .venv/bin/activate 2>/dev/null || true"
Enter
Type "export VIRTUAL_ENV_DISABLE_PROMPT=1 PYTHONPATH=src PYTHONUNBUFFERED=1"
Enter
Type "export PS1='$ '"
Enter
Type "rm -rf demo/.labdata && clear"
Enter
Show

# ---- 1. stand up a lab with the credential-capture honeypot ----
Type "# 1. Stand up a lab with the Telnet credential-capture honeypot"
Enter
Type "python -m lyrebird --config demo/lyrebird.honeypot.yaml &"
Enter
Sleep 3s

# ---- 2. a Mirai-style sample brute-forces, then pulls a second stage ----
Type "# 2. A Mirai-style 'sample' brute-forces Telnet, then pulls a second stage"
Enter
Type "python demo/telnet_client.py"
Enter
Sleep 3s

# ---- 3. the payoff: brute-force + payload-pull captured as tagged JSONL ----
Type "# 3. The honeypot captured every credential AND the payload-pull URL"
Enter
Type "jq -C 'select(.tags|length>0) | {summary, tags}' demo/.labdata/events/honeypot.jsonl"
Enter
Sleep 5s

# ---- tear down (hidden; the clip rests on the payoff) ----
Hide
Type "pkill -f 'lyrebird --config demo/lyrebird.honeypot' 2>/dev/null || true"
Enter
