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

**1. Goal ordering silently breaks rules that test unbound variables.**
The lateral movement rule initially produced zero results. The clause called `is_internal(Src)` before any goal had bound `Src`, and the `atom(IP)` guard inside `is_internal/1` simply fails for an unbound variable rather than throwing an instantiation error. The whole clause failed quietly. The fix was adding `connection(_, Src, _, _, _, _)` as the first goal to generate candidate values before the test runs. The broader pattern is that any predicate doing type or domain checking (`atom/1`, `number/1`, range checks) must come after a generator that grounds the variable. There is no compile-time enforcement of this, so the failure mode is always silent.

**2. Sliding-window `threat/3` clauses require explicit deduplication at the reporting layer.**
Each `threat/3` clause anchors on an individual `connection/6` fact and checks a time window forward from that anchor. A port scan with 12 packets therefore produces 12 solutions, all with the same `(Type, Key)` pair but slightly different evidence terms. Building deduplication into the rule itself (for example, with a cut or a `\+` check against already-reported threats) would couple detection to reporting and prevent interactive querying of individual threats. The cleaner approach is to keep `threat/3` purely generative and handle deduplication in `unique_threats/1` using `findall` to collect all `(Type, Key)` pairs, `list_to_set` to deduplicate, and `once/1` to retrieve one evidence term per pair.

**3. Non-exported dynamic predicates require module-qualified access from outside the module.**
Facts asserted via `assertz(connection(...))` inside `network_monitor` are not listed in the module's export declaration. Code in `web_gui` that accesses them directly as `connection(...)` gets an existence error at runtime, even though the module is loaded. The qualified form `network_monitor:connection(...)` works and is the right call: exporting dynamic predicates would allow any module to retract them, which is a meaningful encapsulation boundary to preserve. The practical consequence is that any helper predicate in a secondary module that aggregates over the fact base needs the module qualifier on every access, including inside `findall` and `aggregate_all` goals.
