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

**1. `current_output` in an HTTP handler is the CGI response stream.**
SWI-Prolog's `library(http/thread_httpd)` binds `current_output` to the raw HTTP socket stream for the duration of each request handler. Any predicate that writes to `current_output` — including deeply nested ones like the `format("[+] Loaded ...")` calls inside the log loaders — will inject bytes into the HTTP body before `reply_json_dict/1` sets the `Content-Type` header, causing a 500 "CGI stream was discarded" error. The fix is to wrap the call in `with_output_to(user_error, Goal)`, passing the stream alias directly. `with_output_to(stream(user_error), Goal)` looks plausible but is a type error — `stream/1` is not a valid target specifier; the alias must be bare.

**2. `process_create/3` with a pipe requires a specific teardown order to avoid deadlock and zombies.**
When calling tshark via `process_create(path(tshark), Args, [stdout(pipe(Out)), process(PID)])`, the teardown sequence is: read the stream fully → `close(Out)` → `process_wait(PID, _)`. Skipping `process_wait` leaves tshark as a zombie because SWI-Prolog does not auto-reap processes created with the `process(PID)` option. More subtly, calling `process_wait` *before* closing the pipe can deadlock: if tshark's output fills the OS pipe buffer, tshark blocks on write, your reader blocks on `process_wait`, and neither side makes progress. The pipe must be drained and closed first.

**3. PCAP's `orig_len` field lets you simulate large transfers without large files.**
Each PCAP packet record contains two length fields: `incl_len` (bytes stored on disk) and `orig_len` (original wire size). tshark exposes `orig_len` as `frame.len`. Because individual Ethernet frames are capped at 65535 bytes, detecting a 15 MB exfil event from a PCAP would normally require session-level reassembly across hundreds of frames. Instead, writing a single minimal frame (just headers, ~60 bytes) with `orig_len = 15_728_640` makes tshark report a 15 MB transfer, which is exactly what the exfil detection rule sees. This is the same mechanism packet capture tools use when recording truncated frames — the distinction between what was captured and what was on the wire is built into the format.
