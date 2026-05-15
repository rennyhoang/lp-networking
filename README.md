# Network Intrusion Detection with Logic Programming

## What It Is

This project uses SWI-Prolog to model how a network administrator reasons about threats. Rather than writing imperative `if/else` checks, the system expresses each threat pattern as a logical rule — a Prolog clause that succeeds when the evidence in the loaded logs satisfies that pattern.

Five threat categories are covered:

| Rule | What it catches |
|---|---|
| `port_scan` | One source probing ≥10 distinct ports on a single host within 60 seconds |
| `brute_force` | ≥5 failed authentication attempts from the same source within 5 minutes |
| `data_exfiltration` | A single outbound connection from an internal host exceeding 10 MB, with off-hours flagging |
| `lateral_movement` | An internal host connecting to ≥5 distinct internal peers (worm spread / post-compromise recon) |
| `blacklist_hit` | Any traffic to or from a known-malicious IP |

All thresholds are declared in one place at the top of the file. The detection rules, reporting loop, and deduplication are completely decoupled — adding a new rule is a single `threat/3` clause with no other changes required.

---

## Files

| File | Purpose |
|---|---|
| `network_monitor.pl` | Core detection engine — rules, log parsers, PCAP loader |
| `web_gui.pl` | HTTP dashboard server (Chart.js charts, threat list, load panel) |
| `static/index.html` | Single-page dashboard UI (self-contained, no build step) |
| `generate_pcap.py` | Synthetic PCAP generator for testing (stdlib only, no pip deps) |
| `sample_connections.log` | CSV connection log with all five threat scenarios |
| `sample_auth.log` | CSV auth log with brute-force events |
| `sample_syslog_auth.log` | OpenSSH syslog-format auth log |
| `sample.pcap` | Pre-generated PCAP produced by `generate_pcap.py` |

---

## How to Run

**Requires:** SWI-Prolog 8.x (`swipl`). Install via your package manager:
```
sudo pacman -S swi-prolog        # Arch / CachyOS
sudo apt install swi-prolog      # Debian/Ubuntu
brew install swi-prolog          # macOS
```

**PCAP support also requires tshark:**
```
sudo pacman -S wireshark-cli     # Arch / CachyOS
sudo apt install tshark          # Debian/Ubuntu
brew install wireshark           # macOS
```

### Command-line (log files)

**Interactive session:**
```prolog
$ swipl network_monitor.pl
?- load_connection_log('sample_connections.log').
?- load_auth_log('sample_auth.log').
?- analyze.
```

**One-shot (non-interactive):**
```bash
swipl -g "load_connection_log('sample_connections.log'), \
          load_auth_log('sample_auth.log'), analyze, halt." \
      network_monitor.pl
```

**Command-line with arguments:**
```bash
swipl -g main network_monitor.pl -- connections.log auth.log
```

**Auth logs** are accepted in two formats automatically — CSV (`unix_ts,src,user,result`) or live OpenSSH syslog format straight from `/var/log/auth.log`.

### PCAP files

**Generate the sample PCAP** (covers all five threat scenarios):
```bash
python3 generate_pcap.py sample.pcap
```

**Load a PCAP in Prolog** (calls tshark internally):
```prolog
$ swipl network_monitor.pl
?- load_pcap('sample.pcap').
?- analyze.
```

**One-shot:**
```bash
swipl -g "load_pcap('sample.pcap'), analyze, halt." network_monitor.pl
```

### Web GUI

Start the HTTP dashboard (serves on port 8080 by default):
```bash
swipl -l network_monitor.pl -l web_gui.pl
?- start_server.        % → http://localhost:8080
?- start_server(9090).  % custom port
```

The dashboard auto-refreshes every 10 seconds and provides:
- Summary cards (connection count, auth events, blacklisted IPs, threat count)
- Four charts: connections over time, protocol distribution, top source IPs, auth timeline
- Threat list with severity badges and evidence
- Load panel to point the server at log files or PCAPs by path

**Other runtime predicates:**

```prolog
?- add_to_blacklist('10.20.30.40').   % add IP to blacklist at runtime
?- clear_data.                         % retract all loaded facts
?- threat(brute_force, Key, Evidence). % query individual rules
?- threat(lateral_movement, Key, Evidence).
```

---

## Lessons Learned

**1. Logic programming forces you to think in terms of what is true, not what to do.**
Each detection rule reads almost like a policy document: *"a port scan exists when one source contacts many distinct ports on the same destination within a window."* This made the rules easy to review and reason about, which is exactly what you want for security logic.

**2. Variables must be ground before procedural predicates see them.**
The lateral movement rule initially failed silently because `is_internal(Src)` was called before any fact had bound `Src`. Prolog's `atom(IP)` guard returned false for an unbound variable and the clause just failed — no error, no warning. The fix was to put a `connection(_, Src, _, _, _, _)` fact first to generate candidate values. This is a fundamental Prolog pattern: *generate, then test*. Getting the order wrong costs nothing at compile time but breaks everything at runtime.

**3. Backtracking is power and a performance trap at the same time.**
The sliding-window rules fire once per anchor event, meaning a scan with 12 connection records triggers the port scan rule 12 times. `unique_threats/1` collapses these with `list_to_set` before reporting. For small log files this is fine; for production-scale logs you would precompute aggregations into indexed facts rather than letting Prolog re-scan on each anchor.

**4. `aggregate_all` is the right tool for counting and set collection.**
Using `findall` + `length` for counting works but produces duplicate solutions for set-like questions. `aggregate_all(set(X), Goal, S)` gives a sorted, deduplicated list in one step and made the port scan and lateral movement rules much cleaner.

**5. String handling in Prolog is workable but not its strong suit.**
Parsing real syslog lines with `split_string`, `sub_string`, and `number_string` required careful attention to SWI-Prolog's atom/string distinction (atoms vs. string objects are different types). DCG grammars would be more principled for complex formats, but `split_string` was fast enough for the two formats needed here.

**6. Declarative extensibility is the real win.**
The fact that you can add a new threat rule — say, correlating a failed login with a connection attempt from the same IP within 60 seconds — as a single `threat/3` clause, with zero changes to the reporting or deduplication code, demonstrates why logic programming is a strong fit for rule-based detection systems. The knowledge base (facts) and the inference engine (rules) are completely separate.

**7. PCAP's `orig_len` field enables large-transfer simulation without large files.**
A PCAP record stores two lengths: `incl_len` (bytes actually on disk) and `orig_len` (wire size). tshark surfaces `orig_len` as `frame.len`. By writing a minimal 60-byte frame with `orig_len = 15_728_640`, the exfil detector sees a 15 MB transfer without bloating the test file. This is the same mechanism packet capture tools use when truncating oversized frames.

**8. SWI-Prolog's HTTP handler context hijacks `current_output`.**
In an HTTP request handler, `current_output` is the CGI response stream. Any `format/1` call inside a loader predicate writes directly into the HTTP body before headers are set — causing a 500 error. The fix is `with_output_to(user_error, Goal)`, which redirects console output to stderr and leaves the response stream clean for `reply_json_dict/1`.

**9. Child processes need explicit cleanup to avoid zombies.**
`process_create/3` with the `process(PID)` option defers waiting so you can read the output pipe first. Without a matching `process_wait(PID, _)` after closing the pipe, the tshark process lingers as a zombie. The pattern is: open pipe → read stream → close pipe → wait for PID.
